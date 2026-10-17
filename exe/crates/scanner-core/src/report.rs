use crate::model::{CoverageStatus, ScanReport};
use chrono::Utc;
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("report I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn choose_report_dir() -> Result<PathBuf, ReportError> {
    let near = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|x| x.join("Reports")));
    let mut options = Vec::new();
    if let Some(p) = near {
        options.push(p);
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        options.push(
            PathBuf::from(local)
                .join("MinecraftCheatScanner")
                .join("Reports"),
        );
    }
    options.push(
        std::env::temp_dir()
            .join("MinecraftCheatScanner")
            .join("Reports"),
    );
    for path in options {
        if fs::create_dir_all(&path).is_err() {
            continue;
        }
        let probe = path.join(".write-test");
        if fs::write(&probe, b"test").is_ok() {
            let _ = fs::remove_file(probe);
            return Ok(path);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "no writable report directory",
    )
    .into())
}

pub fn write_reports(r: &ScanReport, dir: &Path) -> Result<Vec<PathBuf>, ReportError> {
    fs::create_dir_all(dir)?;
    let stem = format!(
        "Minecraft-Cheat-Scan-{}_{}_{:09}",
        Utc::now().format("%Y-%m-%d_%H%M%S"),
        std::process::id(),
        r.completed_utc.timestamp_subsec_nanos()
    );
    let json = serde_json::to_string_pretty(r)?;
    let incomplete = r
        .coverage
        .iter()
        .filter(|c| c.status != CoverageStatus::Completed)
        .count();

    let mut txt = String::new();
    txt.push_str("MINECRAFT CHEAT SCAN\n\n");
    txt.push_str(&format!(
        "Completed: {}\nStatus: {}\nScanner: {}\nUser: {}\n",
        r.completed_utc,
        if r.canceled {
            "Canceled (partial results)"
        } else {
            "Completed"
        },
        r.scanner_version,
        r.user
    ));
    txt.push_str(&format!(
        "Profiles discovered: {}\nMinecraft processes confirmed: {}\nMods analyzed: {}\n\n",
        r.profiles.len(),
        r.processes.iter().filter(|p| p.confirmed_minecraft).count(),
        r.mods.len()
    ));
    if let Some(path) = &r.reports_directory {
        txt.push_str(&format!("Reports directory: {}\n\n", path.display()));
    }
    for p in r.processes.iter().filter(|p| p.confirmed_minecraft) {
        txt.push_str(&format!("Minecraft process: {} (PID {})\nExecutable: {}\nOwner query: {}\nProfile: {}\nLoaded modules: {} ({})\nJVMTI: {}\n", p.name, p.pid, p.executable.as_ref().map(|x| x.display().to_string()).unwrap_or_else(|| "unavailable".into()), p.owner_status, p.profile.as_deref().unwrap_or("unmatched"), p.modules.len(), p.module_status, p.jvm_agent_status));
    }
    if !r.findings.is_empty() {
        txt.push_str("\nDETECTED CHEATS\n");
        for f in &r.findings {
            txt.push_str(&format!(
                "[DETECTED] {}\nCategory: {}\nEvidence: {} ({})\nConfidence: {}\nTimestamp: {}\n",
                f.client_name,
                f.category,
                f.evidence_type,
                f.detection_method,
                f.confidence,
                f.timestamp
            ));
            if let Some(path) = &f.path {
                txt.push_str(&format!("Path: {}\n", path.display()));
            }
            if let Some(hash) = &f.sha256 {
                txt.push_str(&format!("SHA-256: {hash}\n"));
            }
            if let Some(pid) = f.process_id {
                txt.push_str(&format!("Process ID: {pid}\n"));
            }
            if let Some(profile) = &f.profile {
                txt.push_str(&format!("Minecraft profile: {profile}\n"));
            }
            txt.push_str(&format!(
                "Source: {}\nLimitations: {}\n\n",
                f.source, f.limitations
            ));
        }
    }
    txt.push_str(&format!("SCAN COVERAGE\nIncomplete checks: {incomplete}\n"));
    for c in &r.coverage {
        txt.push_str(&format!("{:?}: {} - {}\n", c.status, c.check, c.detail));
    }
    txt.push_str("\nAn empty findings list does not establish that no cheat is present.\n");

    let mut html = String::from("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Minecraft Cheat Scan</title><style>body{font:16px system-ui;background:#10151d;color:#e8edf5;max-width:1000px;margin:2rem auto;padding:0 1rem}section,article{background:#1b2430;border:1px solid #344256;border-radius:12px;padding:1rem;margin:1rem 0}.finding{border-left:5px solid #f05252}input{padding:.6rem;width:98%}table{border-collapse:collapse;width:100%}td,th{padding:.6rem;border-bottom:1px solid #344256;text-align:left;vertical-align:top}.muted{color:#b2bdcc}</style><body><h1>Minecraft Cheat Scan</h1>");
    html.push_str(&format!("<section><b>Completed:</b> {}<br><b>Status:</b> {}<br><b>Profiles:</b> {}<br><b>Confirmed Minecraft processes:</b> {}<br><b>Mods analyzed:</b> {}", esc(&r.completed_utc.to_rfc3339()), if r.canceled { "Canceled (partial results)" } else { "Completed" }, r.profiles.len(), r.processes.iter().filter(|p| p.confirmed_minecraft).count(), r.mods.len()));
    if let Some(path) = &r.reports_directory {
        html.push_str(&format!(
            "<br><b>Reports directory:</b> {}",
            esc(&path.display().to_string())
        ));
    }
    html.push_str(
        "<p class=\"muted\">An empty findings list does not establish absence of cheats.</p>",
    );
    for p in r.processes.iter().filter(|p| p.confirmed_minecraft) {
        html.push_str(&format!("<article><b>{} (PID {})</b><br>Profile: {}<br>Executable: {}<br>Modules: {}<br>JVMTI: {}</article>", esc(&p.name), p.pid, esc(p.profile.as_deref().unwrap_or("unmatched")), esc(&p.executable.as_ref().map(|x| x.display().to_string()).unwrap_or_else(|| "unavailable".into())), p.modules.len(), esc(&p.jvm_agent_status)));
    }
    if !r.findings.is_empty() {
        html.push_str(
            "<section><h2>Detected cheats</h2><input id=\"q\" placeholder=\"Search findings\">",
        );
        for f in &r.findings {
            html.push_str(&format!("<article class=\"finding\"><b>{}</b> - {}<p>Evidence: {} | {}</p><p>Confidence: {}</p><p>Location: {}</p><p>Process: {}</p><p>Profile: {}</p><p>SHA-256: {}</p><p>Timestamp: {}</p><p>Source: {}</p><p>Limitations: {}</p></article>",
                esc(&f.client_name), esc(&f.category), esc(&f.evidence_type), esc(&f.detection_method), esc(&f.confidence),
                esc(&f.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "Runtime-only".into())),
                f.process_id.map(|x| x.to_string()).unwrap_or_else(|| "Not associated".into()),
                esc(f.profile.as_deref().unwrap_or("Not correlated")), esc(f.sha256.as_deref().unwrap_or("Not applicable")),
                esc(&f.timestamp.to_rfc3339()), esc(&f.source), esc(&f.limitations)));
        }
        html.push_str("</section>");
    }
    html.push_str(&format!("<section><h2>Scan coverage</h2><p>Incomplete checks: {incomplete}</p><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>"));
    for c in &r.coverage {
        html.push_str(&format!(
            "<tr><td>{:?}</td><td>{}</td><td>{}</td></tr>",
            c.status,
            esc(&c.check),
            esc(&c.detail)
        ));
    }
    html.push_str("</table></section><script>const q=document.querySelector('#q');if(q)q.oninput=()=>document.querySelectorAll('.finding').forEach(x=>x.hidden=!x.innerText.toLowerCase().includes(q.value.toLowerCase()));</script></body></html>");

    let mut log = format!(
        "Minecraft Cheat Scanner {} diagnostics\nScan ID: {}\nStarted: {}\nCompleted: {}\n",
        r.scanner_version, r.scan_id, r.started_utc, r.completed_utc
    );
    for c in &r.coverage {
        log.push_str(&format!("{:?} | {} | {}\n", c.status, c.check, c.detail));
    }
    for d in &r.diagnostics {
        log.push_str(&format!("DIAGNOSTIC | {d}\n"));
    }
    let paths = vec![
        dir.join(format!("{stem}.txt")),
        dir.join(format!("{stem}.html")),
        dir.join(format!("{stem}.json")),
        dir.join(format!("{stem}-diagnostics.log")),
    ];
    fs::write(&paths[0], txt)?;
    fs::write(&paths[1], html)?;
    fs::write(&paths[2], json)?;
    fs::write(&paths[3], log)?;
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;
    #[test]
    fn html_escapes_untrusted_text() {
        assert_eq!(
            esc("<img a='x'>&\""),
            "&lt;img a=&#39;x&#39;&gt;&amp;&quot;"
        );
    }
    #[test]
    fn no_findings_omits_cheat_section() {
        let now = Utc::now();
        let r = ScanReport {
            schema_version: 1,
            scanner_version: "8".into(),
            scan_id: "test".into(),
            started_utc: now,
            completed_utc: now,
            user: "test".into(),
            profiles: vec![],
            processes: vec![],
            mods: vec![],
            findings: vec![],
            coverage: vec![],
            diagnostics: vec![],
            canceled: false,
            reports_directory: None,
        };
        let d = std::env::temp_dir().join(format!("mcscanner-report-test-{}", std::process::id()));
        let paths = write_reports(&r, &d).unwrap();
        assert!(!std::fs::read_to_string(&paths[0])
            .unwrap()
            .contains("DETECTED CHEATS"));
        assert!(!std::fs::read_to_string(&paths[1])
            .unwrap()
            .contains("Detected cheats"));
        let _ = std::fs::remove_dir_all(d);
    }
    #[test]
    fn positive_finding_is_rendered_and_html_encoded() {
        let now = Utc::now();
        let mut r = ScanReport {
            schema_version: 1,
            scanner_version: "8".into(),
            scan_id: "test".into(),
            started_utc: now,
            completed_utc: now,
            user: "test".into(),
            profiles: vec![],
            processes: vec![],
            mods: vec![],
            findings: vec![Finding {
                client_name: "<Synthetic Client>".into(),
                category: "Fixture".into(),
                evidence_type: "Confirmed artifact match".into(),
                detection_method: "Exact digest".into(),
                confidence: "Verified".into(),
                path: None,
                sha256: Some("a".repeat(64)),
                process_id: Some(42),
                profile: Some("Fixture profile".into()),
                timestamp: now,
                source: "Synthetic test provenance".into(),
                limitations: "Fixture only".into(),
            }],
            coverage: vec![],
            diagnostics: vec![],
            canceled: false,
            reports_directory: None,
        };
        let d = std::env::temp_dir().join(format!(
            "mcscanner-positive-report-test-{}",
            std::process::id()
        ));
        r.reports_directory = Some(d.clone());
        let paths = write_reports(&r, &d).unwrap();
        let txt = std::fs::read_to_string(&paths[0]).unwrap();
        let html = std::fs::read_to_string(&paths[1]).unwrap();
        let json = std::fs::read_to_string(&paths[2]).unwrap();
        assert!(txt.contains("[DETECTED] <Synthetic Client>"));
        assert!(txt.contains("Process ID: 42"));
        assert!(html.contains("&lt;Synthetic Client&gt;"));
        assert!(!html.contains("<Synthetic Client>"));
        assert!(html.contains("Synthetic test provenance"));
        assert!(json.contains("Synthetic Client"));
        assert!(json.contains("Fixture profile"));
        let _ = std::fs::remove_dir_all(d);
    }
}
