#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;
use scanner_core::{run_scan, ScanEvent, ScanReport};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    time::SystemTime,
};

mod embedded_agent {
    include!(concat!(env!("OUT_DIR"), "/embedded_agent.rs"));
}

#[used]
static NATIVE_BUILD_ID: &str = "MCS_NATIVE_RUST_SCANNER_V8";

const EMBEDDED_ICON: &[u8] = include_bytes!("../../../assets/scanner.ico");

struct StartupLog {
    path: Option<PathBuf>,
}

impl StartupLog {
    fn initialize() -> Self {
        let mut candidates = Vec::new();
        if let Some(path) = std::env::var_os("MCS_DIAGNOSTICS_DIR") {
            candidates.push(PathBuf::from(path));
        }
        if let Some(path) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(
                PathBuf::from(path)
                    .join("MinecraftCheatScanner")
                    .join("Logs"),
            );
        }
        candidates.push(
            std::env::temp_dir()
                .join("MinecraftCheatScanner")
                .join("Logs"),
        );

        for directory in candidates {
            if fs::create_dir_all(&directory).is_err() {
                continue;
            }
            let path = directory.join("startup.log");
            if fs::metadata(&path).is_ok_and(|metadata| metadata.len() > 1024 * 1024) {
                let _ = fs::write(&path, b"");
            }
            if OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .is_ok()
            {
                return Self { path: Some(path) };
            }
        }
        Self { path: None }
    }

    fn record(&self, stage: &str, message: &str) {
        let safe_message = redact_user_paths(message);
        let elapsed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let line = format!("{elapsed} [{stage}] {safe_message}\r\n");
        if let Some(path) = &self.path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                if file.write_all(line.as_bytes()).is_ok() {
                    return;
                }
            }
        }
        eprintln!("{line}");
    }

    fn is_available(&self) -> bool {
        self.path.is_some()
    }
}

fn redact_user_paths(message: &str) -> String {
    let mut redacted = message.to_owned();
    for name in ["USERPROFILE", "LOCALAPPDATA", "APPDATA"] {
        if let Some(path) = std::env::var_os(name) {
            let path = PathBuf::from(path).to_string_lossy().into_owned();
            if !path.is_empty() {
                redacted = redacted.replace(&path, "<user-path>");
                redacted = redacted.replace(&path.replace('\\', "/"), "<user-path>");
            }
        }
    }
    redacted
}

fn validate_embedded_app_resources(log: &StartupLog) -> Result<String, String> {
    if EMBEDDED_ICON.len() < 6 || EMBEDDED_ICON[..4] != [0, 0, 1, 0] {
        return Err("embedded application icon is missing or invalid".into());
    }
    log.record("resources", "embedded application icon validated");

    let (catalog_version, signatures) = scanner_core::validate_embedded_catalog()
        .map_err(|error| format!("embedded signature catalog validation failed: {error}"))?;
    log.record(
        "scanner-core",
        &format!("embedded signature catalog validated; {signatures} entries"),
    );

    let agent_status = match embedded_agent::EMBEDDED_AGENT {
        Some(agent) if is_x64_dll(agent) => {
            log.record(
                "resources",
                "embedded optional JVMTI agent validated as x64 DLL",
            );
            "available and valid"
        }
        Some(_) => return Err("embedded JVMTI agent is not a valid x64 DLL".into()),
        None => {
            log.record(
                "resources",
                "optional JVMTI agent is not embedded in this build",
            );
            "not embedded (optional)"
        }
    };

    let _context = egui::Context::default();
    let _application_state = ScannerApp::default();
    log.record(
        "gui",
        "egui context and application state initialized; no native window was opened",
    );

    Ok(format!(
        "self-test passed; signature catalog {catalog_version} ({signatures} entries); JVMTI agent {agent_status}; GUI state initialized"
    ))
}

#[derive(Default)]
struct AppState {
    running: bool,
    percent: u8,
    stage: String,
    detail: String,
    report: Option<ScanReport>,
    error: Option<String>,
    cancel: Option<Arc<AtomicBool>>,
    receiver: Option<Receiver<ScanEvent>>,
}
impl AppState {
    fn start(&mut self) {
        if self.running {
            return;
        }
        let token = Arc::new(AtomicBool::new(false));
        let worker_token = token.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let tx_progress = tx.clone();
            match run_scan(worker_token, move |event| {
                let _ = tx_progress.send(event);
            }) {
                Ok(r) => {
                    let _ = tx.send(ScanEvent::Finished(r));
                }
                Err(e) => {
                    let _ = tx.send(ScanEvent::Error(e));
                }
            }
        });
        self.running = true;
        self.percent = 0;
        self.stage = "Starting".into();
        self.detail = "Preparing bounded local scan".into();
        self.report = None;
        self.error = None;
        self.cancel = Some(token);
        self.receiver = Some(rx);
    }
    fn poll(&mut self) {
        let Some(rx) = &self.receiver else { return };
        while let Ok(ev) = rx.try_recv() {
            match ev {
                ScanEvent::Progress {
                    percent,
                    stage,
                    detail,
                } => {
                    self.percent = percent;
                    self.stage = stage;
                    self.detail = detail
                }
                ScanEvent::Finished(r) => {
                    self.report = Some(r);
                    self.running = false;
                    self.cancel = None
                }
                ScanEvent::Error(e) => {
                    self.error = Some(e);
                    self.running = false;
                    self.cancel = None
                }
            }
        }
    }
}
struct ScannerApp {
    state: AppState,
    extracted_agent: Option<std::path::PathBuf>,
    agent_error: Option<String>,
}
impl Default for ScannerApp {
    fn default() -> Self {
        Self {
            state: AppState::default(),
            extracted_agent: None,
            agent_error: None,
        }
    }
}
impl eframe::App for ScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.poll();
        ctx.request_repaint_after(std::time::Duration::from_millis(150));
        egui::CentralPanel::default().show(ctx,|ui|{
            ui.heading("Minecraft Cheat Scanner");ui.label("Local, read-only scan • Standard user permissions • Minecraft Java Edition");ui.add_space(10.0);
            ui.horizontal(|ui|{if ui.add_enabled(!self.state.running,egui::Button::new("Start Full Scan")).clicked(){self.state.start();}if self.state.running&&ui.button("Cancel scan").clicked(){if let Some(c)=&self.state.cancel{c.store(true,Ordering::Relaxed);}}});
            egui::CollapsingHeader::new("Optional JVM class inspection setup").show(ui,|ui|{
                ui.label("Class inspection requires a new launch of a Minecraft instance you control. This application never injects into or modifies a running JVM and does not edit launcher settings.");
                if embedded_agent::EMBEDDED_AGENT.is_some() {
                    if ui.button("Extract bundled JVMTI agent").clicked() {
                        match extract_embedded_agent() { Ok(path) => { self.extracted_agent = Some(path); self.agent_error = None; }, Err(error) => self.agent_error = Some(error) }
                    }
                    if let Some(path) = &self.extracted_agent {
                        ui.label(format!("Agent: {}", path.display()));
                        ui.label(format!("For a new launch, add this JVM option: -agentpath:\"{}\"", path.display()));
                        ui.label("Remove that JVM option to disable inspection. Keep the extracted DLL while any JVM launched with it is running.");
                    }
                } else {
                    ui.label("This build does not contain the optional x64 JVMTI agent. Passive scanning remains available.");
                }
                if let Some(error) = &self.agent_error { ui.colored_label(egui::Color32::LIGHT_RED, error); }
            });
            if self.state.running{ui.add_space(8.0);ui.add(egui::ProgressBar::new(self.state.percent as f32/100.0).text(format!("{}%",self.state.percent)));ui.strong(&self.state.stage);ui.label(&self.state.detail);}
            if let Some(e)=&self.state.error{ui.colored_label(egui::Color32::LIGHT_RED,format!("Scan could not complete: {e}"));}
            if let Some(r)=&self.state.report{
                ui.add_space(12.0);ui.separator();ui.heading("Scan summary");
                ui.label(format!("Completed: {}",r.completed_utc.to_rfc3339()));
                if let Some(path)=&r.reports_directory{ui.label(format!("Reports folder: {}",path.display()));}
                let identified:Vec<_>=r.processes.iter().filter(|p|p.confirmed_minecraft).collect();
                if identified.is_empty(){ui.label("Minecraft process: not reliably identified in this scan");}else{for p in identified{ui.label(format!("Minecraft process: {} (PID {})",p.name,p.pid));ui.label(format!("Instance: {}",p.profile.as_deref().unwrap_or("Profile correlation unavailable")));}}
                if !r.findings.is_empty(){ui.add_space(6.0);ui.heading("DETECTED CHEATS");for f in &r.findings{egui::Frame::group(ui.style()).show(ui,|ui|{ui.colored_label(egui::Color32::LIGHT_RED,format!("DETECTED: {}",f.client_name));ui.label(format!("Category: {}",f.category));ui.label(format!("Evidence: {} - {}",f.evidence_type,f.detection_method));ui.label(format!("Confidence: {}",f.confidence));if let Some(pid)=f.process_id{ui.label(format!("Process ID: {pid}"));}if let Some(path)=&f.path{ui.label(format!("Location: {}",path.display()));}if let Some(hash)=&f.sha256{ui.label(format!("SHA-256: {hash}"));}ui.label(format!("Limitations: {}",f.limitations));});}}
                ui.add_space(8.0);ui.label("Scan completed. An empty findings list does not prove the absence of cheats.");
                let incomplete=r.coverage.iter().filter(|c|!matches!(c.status,scanner_core::CoverageStatus::Completed)).count();ui.label(format!("Coverage: {incomplete} incomplete, skipped, or restricted check(s). Details are in Reports."));
                egui::CollapsingHeader::new("Runtime inspection results").show(ui,|ui|{ui.label("Class names are reported only when a matching startup agent session was actually queried.");for p in r.processes.iter().filter(|p|p.confirmed_minecraft){ui.label(format!("PID {} ({}) - {} class names, agent status: {}",p.pid,p.name,p.loaded_class_count,p.jvm_agent_status));}});
                egui::CollapsingHeader::new("Coverage details").show(ui,|ui|{for c in &r.coverage{ui.label(format!("{:?} - {}: {}",c.status,c.check,c.detail));}});
            }
        });
    }
}

fn extract_embedded_agent() -> Result<std::path::PathBuf, String> {
    let bytes = embedded_agent::EMBEDDED_AGENT
        .ok_or_else(|| "No embedded agent is available in this build.".to_owned())?;
    if !is_x64_dll(bytes) {
        return Err("The embedded agent failed x64 DLL integrity checks.".into());
    }
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "LOCALAPPDATA is unavailable; the agent was not extracted.".to_owned())?;
    let directory = std::path::PathBuf::from(local)
        .join("MinecraftCheatScanner")
        .join("Agent");
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("Could not create the current-user agent directory: {e}"))?;
    let destination = directory.join("mc-jvmti-agent.dll");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
    {
        Ok(mut file) => {
            use std::io::Write;
            let write_result = file.write_all(bytes).and_then(|_| file.sync_all());
            drop(file);
            if let Err(error) = write_result {
                let _ = std::fs::remove_file(&destination);
                return Err(format!("Could not write the embedded agent: {error}"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(&destination).map_err(|e| {
                format!("An agent file already exists and could not be verified: {e}")
            })?;
            if existing.as_slice() != bytes {
                return Err(format!("An agent file already exists at {} and differs from this embedded build; it was left untouched.", destination.display()));
            }
        }
        Err(error) => return Err(format!("Could not create the agent file: {error}")),
    }
    Ok(destination)
}

fn is_x64_dll(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let Some(header_end) = pe_offset.checked_add(24) else {
        return false;
    };
    if header_end > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return false;
    }
    let machine = u16::from_le_bytes(bytes[pe_offset + 4..pe_offset + 6].try_into().unwrap());
    let characteristics =
        u16::from_le_bytes(bytes[pe_offset + 22..pe_offset + 24].try_into().unwrap());
    machine == 0x8664 && characteristics & 0x2000 != 0
}

fn main() {
    let diagnostics = StartupLog::initialize();
    diagnostics.record("startup", "native Rust scanner entry point reached");
    if !diagnostics.is_available() {
        diagnostics.record(
            "diagnostics",
            "startup log file unavailable; attempting fallback diagnostics output",
        );
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_application(&diagnostics)
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            diagnostics.record("fatal", &error);
            eprintln!(
                "Minecraft Cheat Scanner startup failed: {}",
                redact_user_paths(&error)
            );
            std::process::exit(1);
        }
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic payload");
            diagnostics.record("fatal", &format!("startup panic: {message}"));
            std::process::exit(1);
        }
    }
}

fn run_application(diagnostics: &StartupLog) -> Result<(), String> {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    tracing::info!(build_id = NATIVE_BUILD_ID, "native Rust scanner started");
    diagnostics.record(
        "configuration",
        "using embedded resources and built-in defaults; no external configuration required",
    );
    let (catalog_version, signature_count) = scanner_core::validate_embedded_catalog()
        .map_err(|error| format!("scanner-core initialization failed: {error}"))?;
    diagnostics.record(
        "scanner-core",
        &format!("initialized embedded catalog {catalog_version} with {signature_count} entries"),
    );
    let self_test_summary = validate_embedded_app_resources(diagnostics)?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--self-test") {
        diagnostics.record("self-test", "headless startup checks beginning");
        diagnostics.record("self-test", &format!("PASS: {self_test_summary}"));
        println!("{self_test_summary}; interactive window startup is not tested by this mode");
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--scan-once") {
        diagnostics.record("scanner-core", "initializing one-shot scan");
        run_scan(Arc::new(AtomicBool::new(false)), |_| {})
            .map_err(|error| format!("one-shot scan failed: {error}"))?;
        diagnostics.record("scanner-core", "one-shot scan and reports completed");
        return Ok(());
    }

    diagnostics.record("gui", "creating native eframe window and event loop");
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 650.0])
            .with_min_inner_size([600.0, 460.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Minecraft Cheat Scanner v8.0",
        opts,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::<ScannerApp>::default())
        }),
    )
    .map_err(|error| format!("native GUI initialization/event loop failed: {error}"))?;
    diagnostics.record("gui", "native GUI event loop returned normally");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_x64_dll, EMBEDDED_ICON};

    fn synthetic_pe(machine: u16, characteristics: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        bytes[0x56..0x58].copy_from_slice(&characteristics.to_le_bytes());
        bytes
    }

    #[test]
    fn embedded_agent_validator_accepts_x64_dll_image() {
        assert!(is_x64_dll(&synthetic_pe(0x8664, 0x2022)));
    }

    #[test]
    fn embedded_agent_validator_rejects_wrong_architecture_and_exe() {
        assert!(!is_x64_dll(&synthetic_pe(0x14c, 0x2022)));
        assert!(!is_x64_dll(&synthetic_pe(0x8664, 0x0022)));
    }

    #[test]
    fn embedded_agent_validator_rejects_malformed_headers() {
        assert!(!is_x64_dll(b"MZ"));
        let mut malformed = synthetic_pe(0x8664, 0x2022);
        malformed[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!is_x64_dll(&malformed));
    }

    #[test]
    fn embedded_icon_has_valid_ico_header() {
        assert!(EMBEDDED_ICON.len() >= 6);
        assert_eq!(&EMBEDDED_ICON[..4], &[0, 0, 1, 0]);
        assert_ne!(u16::from_le_bytes([EMBEDDED_ICON[4], EMBEDDED_ICON[5]]), 0);
    }

    #[test]
    fn startup_diagnostics_redact_known_user_paths() {
        let original = std::env::var_os("USERPROFILE");
        if let Some(path) = original {
            let path = std::path::PathBuf::from(path)
                .to_string_lossy()
                .into_owned();
            let redacted = super::redact_user_paths(&format!("failure at {path}"));
            assert!(!redacted.contains(&path));
            assert!(redacted.contains("<user-path>"));
        }
    }
}
