use crate::model::{ModuleRecord, ProcessRecord};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
mod win {
    use super::*;
    use std::{
        ffi::c_void,
        mem::{size_of, zeroed},
        ptr::null_mut,
    };
    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const TH32CS_SNAPMODULE: u32 = 0x00000008;
    const TH32CS_SNAPMODULE32: u32 = 0x00000010;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const MAX_PATH: usize = 260;
    #[repr(C)]
    struct ProcessEntry {
        size: u32,
        usage: u32,
        pid: u32,
        heap: usize,
        module: u32,
        threads: u32,
        parent: u32,
        priority: i32,
        flags: u32,
        name: [u16; MAX_PATH],
    }
    #[repr(C)]
    struct ModuleEntry {
        size: u32,
        module_id: u32,
        pid: u32,
        global_use: u32,
        process_use: u32,
        base: *mut u8,
        size_bytes: u32,
        module: Handle,
        name: [u16; 256],
        path: [u16; MAX_PATH],
    }
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct TokenUser {
        sid: *mut c_void,
        attributes: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry) -> i32;
        fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetLastError() -> u32;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            size: u32,
            needed: *mut u32,
        ) -> i32;
        fn LookupAccountSidW(
            system: *const u16,
            sid: *mut c_void,
            name: *mut u16,
            name_len: *mut u32,
            domain: *mut u16,
            domain_len: *mut u32,
            use_type: *mut u32,
        ) -> i32;
    }
    fn wide(s: &[u16]) -> String {
        String::from_utf16_lossy(&s[..s.iter().position(|c| *c == 0).unwrap_or(s.len())])
    }
    fn created_time(pid: u32) -> Option<(SystemTime, u64)> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut c = zeroed();
            let mut e = zeroed();
            let mut k = zeroed();
            let mut u = zeroed();
            let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u);
            CloseHandle(h);
            if ok == 0 {
                return None;
            }
            let ticks = (((c.high as u64) << 32) | c.low as u64).saturating_sub(116444736000000000)
                / 10_000_000;
            UNIX_EPOCH
                .checked_add(Duration::from_secs(ticks))
                .map(|time| (time, ((c.high as u64) << 32) | c.low as u64))
        }
    }
    fn image_path(pid: u32) -> Option<PathBuf> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 32768];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
        }
    }
    fn owner(pid: u32) -> Result<String, String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return Err(format!("process query denied: Win32 {}", GetLastError()));
            }
            let mut token = null_mut();
            if OpenProcessToken(h, 0x0008, &mut token) == 0 {
                let e = GetLastError();
                CloseHandle(h);
                return Err(format!("OpenProcessToken denied: Win32 {e}"));
            }
            let mut needed = 0;
            let _ = GetTokenInformation(token, 1, null_mut(), 0, &mut needed);
            if needed == 0 {
                let e = GetLastError();
                CloseHandle(token);
                CloseHandle(h);
                return Err(format!("TokenUser query failed: Win32 {e}"));
            }
            let mut storage = vec![0u64; ((needed as usize) + 7) / 8];
            if GetTokenInformation(
                token,
                1,
                storage.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            ) == 0
            {
                let e = GetLastError();
                CloseHandle(token);
                CloseHandle(h);
                return Err(format!("TokenUser query denied: Win32 {e}"));
            }
            let t = &*(storage.as_ptr() as *const TokenUser);
            let mut name = vec![0u16; 512];
            let mut domain = vec![0u16; 512];
            let mut nl = name.len() as u32;
            let mut dl = domain.len() as u32;
            let mut use_type = 0u32;
            let ok = LookupAccountSidW(
                null_mut(),
                t.sid,
                name.as_mut_ptr(),
                &mut nl,
                domain.as_mut_ptr(),
                &mut dl,
                &mut use_type,
            );
            CloseHandle(token);
            CloseHandle(h);
            if ok == 0 {
                return Err(format!("LookupAccountSid failed: Win32 {}", GetLastError()));
            }
            let n = String::from_utf16_lossy(&name[..nl as usize]);
            let d = String::from_utf16_lossy(&domain[..dl as usize]);
            Ok(if d.is_empty() { n } else { format!("{d}\\{n}") })
        }
    }
    pub fn processes() -> Result<Vec<ProcessRecord>, String> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err("CreateToolhelp32Snapshot(processes) failed".into());
            }
            let mut e: ProcessEntry = zeroed();
            e.size = size_of::<ProcessEntry>() as u32;
            let mut out = Vec::new();
            let mut names = std::collections::HashMap::new();
            if Process32FirstW(snap, &mut e) != 0 {
                loop {
                    let name = wide(&e.name);
                    names.insert(e.pid, name.clone());
                    let lower = name.to_ascii_lowercase();
                    if lower == "java.exe" || lower == "javaw.exe" {
                        let path = image_path(e.pid);
                        let created = created_time(e.pid);
                        let (owner_name, owner_status) = match owner(e.pid) {
                            Ok(n) => (Some(n), "Succeeded".to_owned()),
                            Err(err) => (None, format!("Restricted: {err}")),
                        };
                        out.push(ProcessRecord {
                            pid: e.pid,
                            name,
                            executable: path,
                            parent_pid: Some(e.parent),
                            parent_name: None,
                            created_utc: created
                                .map(|t| chrono::DateTime::<chrono::Utc>::from(t.0)),
                            creation_filetime: created.map(|t| t.1),
                            owner: owner_name,
                            owner_status,
                            confirmed_minecraft: false,
                            identification_methods: Vec::new(),
                            profile: None,
                            profile_path: None,
                            modules: Vec::new(),
                            module_status: "Not inspected".into(),
                            jvm_agent_status: "Not checked".into(),
                            loaded_class_count: 0,
                            loaded_class_names: Vec::new(),
                            classloader_count: 0,
                        });
                    }
                    if Process32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            for p in &mut out {
                p.parent_name = p.parent_pid.and_then(|id| names.get(&id).cloned());
            }
            Ok(out)
        }
    }
    pub fn modules(pid: u32) -> Result<Vec<ModuleRecord>, String> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snap == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "module snapshot denied or unavailable (Win32 {})",
                    std::io::Error::last_os_error()
                ));
            }
            let mut e: ModuleEntry = zeroed();
            e.size = size_of::<ModuleEntry>() as u32;
            let mut out = Vec::new();
            if Module32FirstW(snap, &mut e) != 0 {
                loop {
                    let path = wide(&e.path);
                    let name = wide(&e.name);
                    out.push(ModuleRecord {
                        name,
                        path: (!path.is_empty()).then(|| PathBuf::from(path)),
                        base_address: Some(e.base as usize),
                        size_bytes: Some(e.size_bytes),
                        file_exists: false,
                        sha256: None,
                        signature_status: "Not checked".into(),
                    });
                    if Module32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            Ok(out)
        }
    }
}

#[cfg(windows)]
pub fn enumerate_java_processes() -> Result<Vec<ProcessRecord>, String> {
    win::processes()
}
#[cfg(windows)]
pub fn enumerate_modules(pid: u32) -> Result<Vec<ModuleRecord>, String> {
    win::modules(pid)
}

#[cfg(not(windows))]
pub fn enumerate_java_processes() -> Result<Vec<ProcessRecord>, String> {
    Err("Windows process discovery is available only in Windows builds".into())
}
#[cfg(not(windows))]
pub fn enumerate_modules(_pid: u32) -> Result<Vec<ModuleRecord>, String> {
    Err("Windows module inspection is available only in Windows builds".into())
}

pub fn classify_minecraft_process(process: &mut ProcessRecord) {
    let mut methods = Vec::new();
    if let Some(path) = &process.executable {
        let p = path.to_string_lossy().to_ascii_lowercase();
        if [
            "modrinthapp",
            "prismlauncher",
            "multimc",
            "atlauncher",
            "curseforge",
            "minecraft launcher",
        ]
        .iter()
        .any(|x| p.contains(x))
        {
            methods.push("launcher-managed Java runtime path".to_owned());
        }
    }
    if process.parent_name.as_ref().is_some_and(|n| {
        [
            "modrinth",
            "prism",
            "multimc",
            "minecraft launcher",
            "curseforge",
            "atlauncher",
        ]
        .iter()
        .any(|s| n.to_ascii_lowercase().contains(*s))
    }) {
        methods.push("Minecraft launcher parent process".into());
    }
    let mut lwjgl = false;
    let mut openal = false;
    for m in &process.modules {
        let n = m.name.to_ascii_lowercase();
        if n.contains("lwjgl") {
            lwjgl = true;
        }
        if n.contains("openal") {
            openal = true;
        }
    }
    if lwjgl {
        methods.push("loaded LWJGL module".to_owned());
    }
    if openal {
        methods.push("loaded OpenAL module".to_owned());
    }
    // A launcher Java path or parent is only context. Require a known LWJGL
    // native plus that independent launcher signal. The scan engine may also
    // confirm the LWJGL+OpenAL pair when a unique active profile log matches.
    process.confirmed_minecraft = lwjgl
        && methods
            .iter()
            .any(|m| m.contains("launcher-managed") || m.contains("launcher parent"));
    process.identification_methods = methods;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(path: &str, modules: &[&str]) -> ProcessRecord {
        ProcessRecord {
            pid: 1,
            name: "javaw.exe".into(),
            executable: Some(path.into()),
            parent_pid: None,
            parent_name: None,
            created_utc: None,
            creation_filetime: None,
            owner: None,
            owner_status: String::new(),
            confirmed_minecraft: false,
            identification_methods: vec![],
            profile: None,
            profile_path: None,
            modules: modules
                .iter()
                .map(|n| ModuleRecord {
                    name: (*n).into(),
                    path: None,
                    base_address: None,
                    size_bytes: None,
                    file_exists: false,
                    sha256: None,
                    signature_status: String::new(),
                })
                .collect(),
            module_status: String::new(),
            jvm_agent_status: String::new(),
            loaded_class_count: 0,
            loaded_class_names: vec![],
            classloader_count: 0,
        }
    }
    #[test]
    fn plain_java_is_not_minecraft() {
        let mut x = p("C:\\Java\\bin\\javaw.exe", &[]);
        classify_minecraft_process(&mut x);
        assert!(!x.confirmed_minecraft);
    }
    #[test]
    fn lwjgl_alone_is_not_enough() {
        let mut x = p("C:\\Java\\bin\\javaw.exe", &["lwjgl.dll"]);
        classify_minecraft_process(&mut x);
        assert!(!x.confirmed_minecraft);
    }
    #[test]
    fn common_game_libraries_without_profile_or_launcher_are_not_enough() {
        let mut x = p("C:\\Java\\bin\\javaw.exe", &["lwjgl.dll", "OpenAL.dll"]);
        classify_minecraft_process(&mut x);
        assert!(!x.confirmed_minecraft);
    }
    #[test]
    fn launcher_context_without_game_modules_is_not_enough() {
        let mut x = p(
            "C:\\Users\\User\\AppData\\Roaming\\ModrinthApp\\java\\javaw.exe",
            &[],
        );
        x.parent_name = Some("ModrinthApp.exe".into());
        classify_minecraft_process(&mut x);
        assert!(!x.confirmed_minecraft);
    }
    #[test]
    fn launcher_path_and_lwjgl_correlate() {
        let mut x = p(
            "C:\\Users\\User\\AppData\\Roaming\\ModrinthApp\\java\\javaw.exe",
            &["lwjgl.dll"],
        );
        classify_minecraft_process(&mut x);
        assert!(x.confirmed_minecraft);
    }
}
