use crate::model::ProcessRecord;
use serde::{Deserialize, Serialize};

pub const AGENT_PROTOCOL_VERSION: u32 = 1;
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentEnvelope {
    pub protocol_version: u32,
    pub process_id: u32,
    pub process_creation_filetime: u64,
    pub session_id: String,
    pub classes: Vec<AgentClass>,
    pub error: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentClass {
    pub name: String,
    pub loader_id: u32,
    pub loader_kind: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentMarker {
    protocol_version: u32,
    process_id: u32,
    process_creation_filetime: u64,
    session_id: String,
    pipe_name: String,
}

pub fn class_signature_to_name(s: &str) -> Option<String> {
    if let Some(inner) = s.strip_prefix('L').and_then(|x| x.strip_suffix(';')) {
        return Some(inner.replace('/', "."));
    }
    if let Some(inner) = s.strip_prefix('[') {
        let name = match inner {
            "B" => "byte".into(),
            "C" => "char".into(),
            "D" => "double".into(),
            "F" => "float".into(),
            "I" => "int".into(),
            "J" => "long".into(),
            "S" => "short".into(),
            "Z" => "boolean".into(),
            _ => class_signature_to_name(inner)?,
        };
        return Some(format!("{name}[]"));
    }
    None
}

pub fn validate_agent_response(
    msg: &AgentEnvelope,
    process: &ProcessRecord,
    expected_session: &str,
) -> Result<(), String> {
    if msg.protocol_version != AGENT_PROTOCOL_VERSION {
        return Err(format!("agent protocol mismatch: {}", msg.protocol_version));
    }
    if msg.process_id != process.pid {
        return Err("agent response PID does not match selected Minecraft process".into());
    }
    if Some(msg.process_creation_filetime) != process.creation_filetime {
        return Err("agent response creation time does not match current process".into());
    }
    if msg.session_id != expected_session {
        return Err("agent session token mismatch".into());
    }
    if msg.session_id.is_empty()
        || msg.session_id.len() > 128
        || !msg
            .session_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("agent session identifier is malformed".into());
    }
    if let Some(err) = &msg.error {
        return Err(format!("agent reported an error: {err}"));
    }
    if msg.classes.len() > 500_000 {
        return Err("agent response exceeds class count limit".into());
    }
    if msg
        .classes
        .iter()
        .any(|c| c.name.len() > 2048 || c.loader_kind.len() > 64)
    {
        return Err("agent class entry exceeds field limits".into());
    }
    Ok(())
}

/// Query only a user-configured startup agent. The rendezvous record is bound to
/// both PID and Windows process creation time so PID reuse cannot replay data.
#[cfg(windows)]
pub fn inspect_startup_agent(process: &mut ProcessRecord) -> Result<bool, String> {
    use std::{fs, os::windows::ffi::OsStrExt, path::PathBuf, ptr::null_mut};
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("LOCALAPPDATA is unavailable")?
        .join("MinecraftCheatScanner")
        .join("Agent");
    let marker_path = base.join(format!("agent-{}.json", process.pid));
    if !marker_path.is_file() {
        process.jvm_agent_status = "Unavailable: no startup agent rendezvous file".into();
        return Ok(false);
    }
    let meta = fs::metadata(&marker_path).map_err(|e| e.to_string())?;
    if meta.len() > 4096 {
        return Err("agent marker exceeds 4 KiB".into());
    }
    let marker: AgentMarker =
        serde_json::from_slice(&fs::read(&marker_path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid agent marker: {e}"))?;
    if marker.protocol_version != AGENT_PROTOCOL_VERSION {
        return Err("agent protocol version mismatch".into());
    }
    if marker.process_id != process.pid
        || Some(marker.process_creation_filetime) != process.creation_filetime
    {
        return Err("agent PID or process creation time does not match current process (stale session rejected)".into());
    }
    if !marker
        .pipe_name
        .starts_with(r"\\.\pipe\MinecraftCheatScanner-v8-")
        || marker.pipe_name.contains("..")
        || marker.pipe_name.len() > 240
        || marker.session_id.is_empty()
        || !marker
            .session_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("agent pipe path or session token failed validation".into());
    }
    let mut pipe: Vec<u16> = std::ffi::OsStr::new(&marker.pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let payload = format!(
        "SCAN {} {} {}\n",
        process.pid, marker.process_creation_filetime, marker.session_id
    );
    unsafe {
        if WaitNamedPipeW(pipe.as_ptr(), 1000) == 0 {
            return Err(format!(
                "JVMTI agent pipe is not listening: {}",
                std::io::Error::last_os_error()
            ));
        }
        let h = CreateFileW(
            pipe.as_mut_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(format!(
                "JVMTI agent pipe unavailable: {}",
                std::io::Error::last_os_error()
            ));
        }
        let result = (|| {
            let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(payload.as_bytes());
            write_overlapped(h, &frame)?;
            let mut len = [0u8; 4];
            read_overlapped(h, &mut len)?;
            let n = u32::from_le_bytes(len) as usize;
            if n == 0 || n > 16 * 1024 * 1024 {
                return Err("agent message exceeds 16 MiB protocol limit".into());
            }
            let mut data = vec![0u8; n];
            read_overlapped(h, &mut data)?;
            let response: AgentEnvelope = serde_json::from_slice(&data)
                .map_err(|e| format!("invalid JVMTI response: {e}"))?;
            validate_agent_response(&response, process, &marker.session_id)?;
            Ok(response)
        })();
        CloseHandle(h);
        let msg = result?;
        process.loaded_class_count = msg.classes.len();
        process.classloader_count = msg
            .classes
            .iter()
            .map(|c| c.loader_id)
            .collect::<std::collections::HashSet<_>>()
            .len();
        process.loaded_class_names = msg
            .classes
            .into_iter()
            .take(100_000)
            .map(|c| c.name)
            .collect();
        process.jvm_agent_status =
            "Connected: startup JVMTI snapshot received and process/session validated".into();
        Ok(true)
    }
}
#[cfg(not(windows))]
pub fn inspect_startup_agent(process: &mut ProcessRecord) -> Result<bool, String> {
    process.jvm_agent_status = "Unavailable on non-Windows builds".into();
    Ok(false)
}

#[cfg(windows)]
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
#[cfg(windows)]
const GENERIC_READ: u32 = 0x80000000;
#[cfg(windows)]
const GENERIC_WRITE: u32 = 0x40000000;
#[cfg(windows)]
const OPEN_EXISTING: u32 = 3;
#[cfg(windows)]
const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
#[cfg(windows)]
const ERROR_IO_PENDING: u32 = 997;
#[cfg(windows)]
const WAIT_OBJECT_0: u32 = 0;
#[cfg(windows)]
const WAIT_TIMEOUT: u32 = 258;
#[cfg(windows)]
#[repr(C)]
struct Offset {
    offset: u32,
    offset_high: u32,
}
#[cfg(windows)]
#[repr(C)]
union OverlapOffset {
    offset: Offset,
    pointer: *mut std::ffi::c_void,
}
#[cfg(windows)]
#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    position: OverlapOffset,
    event: *mut std::ffi::c_void,
}
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut std::ffi::c_void,
        creation: u32,
        flags: u32,
        template: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
    fn CreateEventW(
        security: *mut std::ffi::c_void,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, ms: u32) -> u32;
    fn GetOverlappedResult(
        handle: *mut std::ffi::c_void,
        overlap: *mut Overlapped,
        transferred: *mut u32,
        wait: i32,
    ) -> i32;
    fn CancelIoEx(handle: *mut std::ffi::c_void, overlap: *mut Overlapped) -> i32;
    fn ReadFile(
        handle: *mut std::ffi::c_void,
        buffer: *mut u8,
        len: u32,
        transferred: *mut u32,
        overlap: *mut Overlapped,
    ) -> i32;
    fn WriteFile(
        handle: *mut std::ffi::c_void,
        buffer: *const u8,
        len: u32,
        transferred: *mut u32,
        overlap: *mut Overlapped,
    ) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}
#[cfg(windows)]
fn transfer_result(
    h: *mut std::ffi::c_void,
    ov: &mut Overlapped,
    n: &mut u32,
    ok: i32,
) -> Result<(), String> {
    if ok != 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
        return Err(e.to_string());
    }
    let w = unsafe { WaitForSingleObject(ov.event, 3000) };
    if w == WAIT_TIMEOUT {
        unsafe {
            CancelIoEx(h, ov);
        }
        return Err("JVMTI pipe operation timed out after 3 seconds".into());
    }
    if w != WAIT_OBJECT_0 {
        return Err("JVMTI pipe wait failed".into());
    }
    if unsafe { GetOverlappedResult(h, ov, n, 0) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}
#[cfg(windows)]
fn new_overlap(event: *mut std::ffi::c_void) -> Overlapped {
    Overlapped {
        internal: 0,
        internal_high: 0,
        position: OverlapOffset {
            offset: Offset {
                offset: 0,
                offset_high: 0,
            },
        },
        event,
    }
}
#[cfg(windows)]
fn write_overlapped(h: *mut std::ffi::c_void, data: &[u8]) -> Result<(), String> {
    let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut ov = new_overlap(event);
    let mut n = 0;
    let ok = unsafe { WriteFile(h, data.as_ptr(), data.len() as u32, &mut n, &mut ov) };
    let result = transfer_result(h, &mut ov, &mut n, ok);
    unsafe { CloseHandle(event) };
    result?;
    if n as usize != data.len() {
        return Err("short write on JVMTI pipe".into());
    }
    Ok(())
}
#[cfg(windows)]
fn read_overlapped(h: *mut std::ffi::c_void, data: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < data.len() {
        let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut ov = new_overlap(event);
        let mut n = 0;
        let ok = unsafe {
            ReadFile(
                h,
                data[offset..].as_mut_ptr(),
                (data.len() - offset) as u32,
                &mut n,
                &mut ov,
            )
        };
        let result = transfer_result(h, &mut ov, &mut n, ok);
        unsafe { CloseHandle(event) };
        result?;
        if n == 0 {
            return Err("JVMTI pipe closed before full response".into());
        }
        offset += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn converts_jvm_signatures() {
        assert_eq!(
            class_signature_to_name("Lnet/minecraft/client/Minecraft;"),
            Some("net.minecraft.client.Minecraft".into())
        );
        assert_eq!(
            class_signature_to_name("[Ljava/lang/String;"),
            Some("java.lang.String[]".into())
        );
    }
    #[test]
    fn rejects_wrong_process() {
        let p = ProcessRecord {
            pid: 20,
            name: "javaw.exe".into(),
            executable: None,
            parent_pid: None,
            parent_name: None,
            created_utc: None,
            creation_filetime: None,
            owner: None,
            owner_status: String::new(),
            confirmed_minecraft: true,
            identification_methods: vec![],
            profile: None,
            profile_path: None,
            modules: vec![],
            module_status: String::new(),
            jvm_agent_status: String::new(),
            loaded_class_count: 0,
            loaded_class_names: vec![],
            classloader_count: 0,
        };
        let m = AgentEnvelope {
            protocol_version: 1,
            process_id: 21,
            process_creation_filetime: 1,
            session_id: "x".into(),
            classes: vec![],
            error: None,
        };
        assert!(validate_agent_response(&m, &p, "x").is_err());
    }
}
