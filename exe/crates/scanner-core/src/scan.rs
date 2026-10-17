use crate::{
    archive, discovery,
    model::{Coverage, CoverageStatus, Finding, ProcessRecord, ScanReport},
    process, report,
    signatures::Catalog,
};
use chrono::{DateTime, Utc};
use std::{
    env,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::SystemTime,
};

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Progress {
        percent: u8,
        stage: String,
        detail: String,
    },
    Finished(ScanReport),
    Error(String),
}
fn emit<F: FnMut(ScanEvent)>(f: &mut F, percent: u8, stage: &str, detail: &str) {
    f(ScanEvent::Progress {
        percent,
        stage: stage.into(),
        detail: detail.into(),
    })
}
fn creation_diff(a: Option<DateTime<Utc>>, b: SystemTime) -> i64 {
    a.map(|x| (x - SystemTimeToDateTime::convert(b)).num_seconds().abs())
        .unwrap_or(i64::MAX)
}
struct SystemTimeToDateTime;
impl SystemTimeToDateTime {
    fn convert(t: SystemTime) -> DateTime<Utc> {
        DateTime::<Utc>::from(t)
    }
}
fn correlate_profile(p: &mut ProcessRecord, profiles: &[crate::model::ProfileRecord]) -> bool {
    let Some(created) = p.created_utc else {
        return false;
    };
    let mut candidates = Vec::new();
    for profile in profiles {
        let Some(logdir) = &profile.log_dir else {
            continue;
        };
        let path = logdir.join("latest.log");
        let Ok(meta) = path.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let delta = creation_diff(Some(created), modified);
        if delta <= 300 {
            candidates.push((delta, profile));
        }
    }
    candidates.sort_by_key(|x| x.0);
    if candidates.is_empty() {
        return false;
    }
    if candidates.len() > 1 && candidates[0].0 == candidates[1].0 {
        return false;
    }
    let (_, profile) = candidates[0];
    p.profile = Some(profile.name.clone());
    p.profile_path = Some(profile.root.clone());
    true
}
fn scan_log_mod_ids(
    profile: &crate::model::ProfileRecord,
) -> std::collections::HashMap<String, String> {
    let Some(log) = profile.log_dir.as_ref().map(|p| p.join("latest.log")) else {
        return Default::default();
    };
    let Ok(text) = std::fs::read_to_string(log) else {
        return Default::default();
    };
    let mut ids = std::collections::HashMap::new();
    for line in text.lines().rev().take(5000) {
        let trimmed = if let Some(i) = line.rfind(" - ") {
            &line[i + 3..]
        } else {
            line.trim().strip_prefix('-').unwrap_or("")
        };
        let trimmed = trimmed.trim();
        if let Some((id, version)) = trimmed.split_once(' ') {
            if id.len() < 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                ids.entry(id.to_ascii_lowercase())
                    .or_insert_with(|| version.trim().to_owned());
            }
        }
    }
    ids
}
fn embedded_catalog() -> Result<Catalog, String> {
    Catalog::parse(include_str!("../../../signatures/signatures.json")).map_err(|e| e.to_string())
}
fn load_catalog() -> Result<Catalog, String> {
    // The catalog is compiled into the executable so portable scans never
    // depend on a neighboring signatures.json that could be stale or altered.
    embedded_catalog()
}
fn user_name() -> String {
    env::var("USERNAME")
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "Current Windows user".into())
}
fn scan_profile_mods<F: FnMut(ScanEvent)>(
    profile: &crate::model::ProfileRecord,
    catalog: &Catalog,
    cancel: &AtomicBool,
    processes: &[ProcessRecord],
    max_items: usize,
    total_items: usize,
    mods: &mut Vec<crate::model::ModRecord>,
    findings: &mut Vec<Finding>,
    coverage: &mut Vec<Coverage>,
    diagnostics: &mut Vec<String>,
    done: &mut usize,
    bytes_hashed: &mut u64,
    progress: &mut F,
) -> usize {
    let Some(dir) = &profile.mods_dir else {
        coverage.push(Coverage::new(
            format!("Mods folder: {}", profile.name),
            CoverageStatus::Skipped,
            "profile has no accessible mods directory",
        ));
        return 0;
    };
    let mut listing = Vec::new();
    let mut listing_truncated = false;
    match std::fs::read_dir(dir) {
        Ok(iter) => {
            for (index, entry) in iter.enumerate() {
                if index >= 50_000 {
                    listing_truncated = true;
                    break;
                }
                match entry {
                    Ok(e) => {
                        if e.file_type().map(|t| t.is_file()).unwrap_or(false)
                            && e.path()
                                .extension()
                                .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
                        {
                            listing.push(e.path());
                        }
                    }
                    Err(e) => coverage.push(Coverage::new(
                        format!("Mod inventory {}", profile.name),
                        CoverageStatus::Partial,
                        e.to_string(),
                    )),
                }
            }
        }
        Err(e) => {
            coverage.push(Coverage::new(
                format!("Mod inventory {}", profile.name),
                CoverageStatus::Partial,
                e.to_string(),
            ));
            return 0;
        }
    }
    if listing.len() > max_items {
        listing.truncate(max_items + 1)
    }
    let entries = listing;
    if listing_truncated {
        coverage.push(Coverage::new(
            format!("Mod inventory: {}", profile.name),
            CoverageStatus::Partial,
            "directory listing exceeded the 50,000 entry bound",
        ));
    }
    if entries.len() > max_items {
        coverage.push(Coverage::new(
            format!("Mod inventory: {}", profile.name),
            CoverageStatus::Partial,
            format!(
                "the global {} JAR limit was reached; remaining files skipped",
                max_items
            ),
        ));
    }
    let running_ids = scan_log_mod_ids(profile);
    let mut scanned = 0;
    for path in entries.into_iter().take(max_items) {
        if cancel.load(Ordering::Relaxed) {
            return scanned;
        }
        *done += 1;
        scanned += 1;
        let pct = if total_items == 0 {
            88
        } else {
            48 + ((*done * 40) / total_items).min(40) as u8
        };
        emit(
            progress,
            pct,
            "Analyze mod JARs",
            &format!(
                "{} - {} / {}",
                path.file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("archive"),
                done,
                total_items
            ),
        );
        let size = match path.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                coverage.push(Coverage::new(
                    format!("Mod file {}", path.display()),
                    CoverageStatus::Partial,
                    e.to_string(),
                ));
                continue;
            }
        };
        let estimated = size.saturating_mul(2);
        if size > 512 * 1024 * 1024
            || (*bytes_hashed).saturating_add(estimated) > 4 * 1024 * 1024 * 1024
        {
            coverage.push(Coverage::new(
                format!("Mod file {}", path.display()),
                CoverageStatus::Partial,
                "per-file or aggregate read budget reached; file skipped",
            ));
            continue;
        }
        *bytes_hashed += estimated;
        match archive::analyze_mod(&path, &profile.name, catalog) {
            Ok((mut record, nested)) => {
                let active = processes.iter().find(|p| {
                    p.confirmed_minecraft && p.profile.as_deref() == Some(profile.name.as_str())
                });
                record.associated_process_id = active.map(|p| p.pid);
                if let Some(id) = record.metadata_id.as_ref().map(|x| x.to_ascii_lowercase()) {
                    if let Some(log_version) = running_ids.get(&id) {
                        record.runtime_log_listed = true;
                        record.runtime_log_version_match =
                            record.version.as_ref().map(|v| v == log_version);
                        record.runtime_association = if record.runtime_log_version_match
                            == Some(true)
                        {
                            "Active profile loader log lists matching mod ID and version; class loading not proven".into()
                        } else {
                            "Active profile loader log lists this mod ID; version differs or is unavailable, and class loading is not proven".into()
                        };
                    }
                }
                if let Some(digest) = record.sha256.as_deref() {
                    if let Some(sig) = catalog.exact_verified_match(digest, "JAR") {
                        findings.push(Finding {
                            client_name: sig.project.clone(),
                            category: "Mod-based client".into(),
                            evidence_type: "Confirmed artifact match".into(),
                            detection_method: "Exact SHA-256 match to catalogued release".into(),
                            confidence: if sig.status == "IndependentlyVerified" {
                                "Independently verified digest"
                            } else {
                                "Official-source digest"
                            }
                            .into(),
                            path: Some(path.clone()),
                            sha256: Some(digest.into()),
                            process_id: None,
                            profile: Some(profile.name.clone()),
                            timestamp: Utc::now(),
                            source: sig.source.clone(),
                            limitations: "Installed artifact does not prove it was loaded or used."
                                .into(),
                        });
                    }
                }
                for (nested_name, nested_digest) in nested {
                    if let Some(sig) = catalog.exact_verified_match(&nested_digest, "JAR") {
                        findings.push(Finding{client_name:sig.project.clone(),category:"Mod-based client".into(),evidence_type:"Confirmed nested artifact match".into(),detection_method:format!("Exact SHA-256 match for nested JAR entry {nested_name}"),confidence:if sig.status=="IndependentlyVerified"{"Independently verified digest"}else{"Official-source digest"}.into(),path:Some(path.clone()),sha256:Some(nested_digest),process_id:None,profile:Some(profile.name.clone()),timestamp:Utc::now(),source:sig.source.clone(),limitations:"Nested release was found inside this archive; installation does not prove it was loaded.".into()});
                    }
                }
                mods.push(record);
            }
            Err(e) => {
                coverage.push(Coverage::new(
                    format!("Archive {}", path.display()),
                    CoverageStatus::Partial,
                    e.to_string(),
                ));
                diagnostics.push(format!("{}: {e}", path.display()));
            }
        }
    }
    scanned
}

pub fn run_scan<F: FnMut(ScanEvent)>(
    cancel: Arc<AtomicBool>,
    mut progress: F,
) -> Result<ScanReport, String> {
    let started = Utc::now();
    let mut coverage = Vec::new();
    let mut diagnostics = Vec::new();
    let mut findings = Vec::new();
    let mut mods = Vec::new();
    emit(
        &mut progress,
        0,
        "Starting",
        "Preparing bounded read-only scan",
    );
    let (profiles, mut discovery_diag) = discovery::discover_profiles();
    diagnostics.append(&mut discovery_diag);
    coverage.push(Coverage::new(
        "Minecraft profile discovery",
        if profiles.is_empty() {
            CoverageStatus::Partial
        } else {
            CoverageStatus::Completed
        },
        format!("Discovered {} profile(s)", profiles.len()),
    ));
    emit(
        &mut progress,
        15,
        "Discover Minecraft installations",
        &format!("{} profile(s)", profiles.len()),
    );
    let catalog = match load_catalog() {
        Ok(c) => {
            coverage.push(Coverage::new(
                "Verified signature catalog",
                CoverageStatus::Completed,
                format!(
                    "Loaded schema v{} catalog {} ({} exact records)",
                    c.schema_version,
                    c.catalog_version,
                    c.entries.len()
                ),
            ));
            c
        }
        Err(e) => {
            coverage.push(Coverage::new(
                "Verified signature catalog",
                CoverageStatus::Failed,
                e.clone(),
            ));
            diagnostics.push(e);
            embedded_catalog()
                .map_err(|x| format!("external and embedded signature catalogs invalid: {x}"))?
        }
    };
    let mut processes = match process::enumerate_java_processes() {
        Ok(p) => {
            coverage.push(Coverage::new(
                "Java process discovery",
                CoverageStatus::Completed,
                format!("{} candidate(s) found", p.len()),
            ));
            p
        }
        Err(e) => {
            coverage.push(Coverage::new(
                "Java process discovery",
                CoverageStatus::Restricted,
                e.clone(),
            ));
            diagnostics.push(e);
            Vec::new()
        }
    };
    let total = processes.len().max(1);
    let mut module_files = 0u64;
    let mut module_bytes = 0u64;
    let mut dll_matched = 0;
    for (i, p) in processes.iter_mut().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let pid = p.pid;
        match process::enumerate_modules(pid) {
            Ok(modules) => {
                p.modules = modules;
                p.module_status = format!("Enumerated {} accessible module(s)", p.modules.len());
            }
            Err(e) => {
                p.module_status = e.clone();
                coverage.push(Coverage::new(
                    format!("Loaded modules PID {pid}"),
                    CoverageStatus::Restricted,
                    e.clone(),
                ));
                diagnostics.push(format!("PID {pid} module inspection: {e}"));
            }
        }
        process::classify_minecraft_process(p);
        let log_profile_match = correlate_profile(p, &profiles);
        if !p.confirmed_minecraft
            && log_profile_match
            && p.identification_methods
                .iter()
                .any(|m| m == "loaded LWJGL module")
            && p.identification_methods
                .iter()
                .any(|m| m == "loaded OpenAL module")
        {
            p.confirmed_minecraft = true;
            p.identification_methods
                .push("unique active profile latest.log startup-time correlation".into());
        }
        if !p.confirmed_minecraft {
            p.profile = None;
            p.profile_path = None;
        }
        if p.confirmed_minecraft {
            if log_profile_match {
                coverage.push(Coverage::new(
                    format!("Active profile PID {pid}"),
                    CoverageStatus::Completed,
                    format!(
                        "Matched {} ({})",
                        p.profile.as_deref().unwrap_or("unknown"),
                        p.profile_path
                            .as_ref()
                            .map(|x| x.display().to_string())
                            .unwrap_or_default()
                    ),
                ));
            } else {
                coverage.push(Coverage::new(format!("Active profile PID {pid}"),CoverageStatus::Partial,"Minecraft process identified, but no unique profile startup-log correlation was available."));
            }
            let profile = p.profile.clone();
            for module in &mut p.modules {
                let Some(path) = module.path.clone() else {
                    continue;
                };
                if !path.is_file() {
                    continue;
                }
                module.file_exists = true;
                module_files += 1;
                let size = match std::fs::metadata(&path) {
                    Ok(m) => m.len(),
                    Err(e) => {
                        coverage.push(Coverage::new(
                            format!("Module file {}", path.display()),
                            CoverageStatus::Partial,
                            e.to_string(),
                        ));
                        continue;
                    }
                };
                if size > 256 * 1024 * 1024
                    || module_bytes.saturating_add(size) > 1024 * 1024 * 1024
                {
                    coverage.push(Coverage::new(
                        format!("Module hash {}", path.display()),
                        CoverageStatus::Partial,
                        "per-module or aggregate 1 GiB hashing limit reached",
                    ));
                    continue;
                }
                module_bytes += size;
                match crate::signatures::sha256_file(&path, 256 * 1024 * 1024) {
                    Ok(digest) => {
                        module.sha256 = Some(digest.clone());
                        if let Some(sig) = catalog.exact_verified_match(&digest, "DLL") {
                            dll_matched += 1;
                            findings.push(Finding{client_name:sig.project.clone(),category:"Injectable/native client".into(),evidence_type:"Confirmed runtime module match".into(),detection_method:"Exact SHA-256 match for loaded file-backed module".into(),confidence:if sig.status=="IndependentlyVerified"{"Independently verified digest"}else{"Official-source digest"}.into(),path:Some(path.clone()),sha256:Some(digest),process_id:Some(pid),profile:profile.clone(),timestamp:Utc::now(),source:sig.source.clone(),limitations:"Only accessible file-backed modules were hashed. Other in-memory code may not be visible.".into()});
                        }
                    }
                    Err(e) => coverage.push(Coverage::new(
                        format!("Module hash {}", path.display()),
                        CoverageStatus::Partial,
                        e.to_string(),
                    )),
                }
            }
            match crate::runtime_correlation::inspect_startup_agent(p){
                Ok(true)=>coverage.push(Coverage::new(format!("JVMTI classes PID {pid}"),CoverageStatus::Completed,format!("Validated startup-agent snapshot: {} class names and {} classloader groups. Class names are observations, not cheat proof.",p.loaded_class_count,p.classloader_count))),
                Ok(false)=>coverage.push(Coverage::new(format!("JVMTI classes PID {pid}"),CoverageStatus::Skipped,p.jvm_agent_status.clone())),
                Err(e)=>{p.jvm_agent_status=format!("Restricted/incomplete: {e}");coverage.push(Coverage::new(format!("JVMTI classes PID {pid}"),CoverageStatus::Partial,e));}
            }
        }
        emit(
            &mut progress,
            20 + ((i + 1) * 25 / total) as u8,
            "Identify running Minecraft processes",
            &format!(
                "PID {pid}: {}",
                if p.confirmed_minecraft {
                    "identified"
                } else {
                    "unconfirmed Java candidate"
                }
            ),
        );
    }
    if processes.is_empty() {
        coverage.push(Coverage::new(
            "Runtime process inspection",
            CoverageStatus::Skipped,
            "No Java process candidates were accessible; offline scan continues.",
        ));
    }
    coverage.push(Coverage::new(
        "File-backed module hashing",
        if module_files == 0 {
            CoverageStatus::Skipped
        } else {
            CoverageStatus::Completed
        },
        format!(
            "Hashed {} accessible module file(s); exact catalog matches={dll_matched}",
            module_files
        ),
    ));
    emit(
        &mut progress,
        48,
        "Analyze installed mods",
        "Preparing bounded per-profile JAR inventory",
    );
    let mut total_jars = 0usize;
    for profile in &profiles {
        if total_jars >= 10_001 {
            break;
        }
        if let Some(dir) = &profile.mods_dir {
            match std::fs::read_dir(dir) {
                Ok(es) => {
                    total_jars = total_jars.saturating_add(
                        es.take(50_000)
                            .filter_map(Result::ok)
                            .filter(|e| {
                                e.file_type().map(|t| t.is_file()).unwrap_or(false)
                                    && e.path()
                                        .extension()
                                        .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
                            })
                            .count(),
                    );
                }
                Err(e) => coverage.push(Coverage::new(
                    format!("Mod inventory {}", profile.name),
                    CoverageStatus::Partial,
                    e.to_string(),
                )),
            }
        }
    }
    const MAX_TOTAL_JARS: usize = 10_000;
    if total_jars > MAX_TOTAL_JARS {
        coverage.push(Coverage::new(
            "Global JAR inventory",
            CoverageStatus::Partial,
            format!(
                "{} candidates found; capped at {MAX_TOTAL_JARS}",
                total_jars
            ),
        ));
        total_jars = MAX_TOTAL_JARS;
    }
    let mut done = 0usize;
    let mut bytes_hashed = 0u64;
    let mut remaining = MAX_TOTAL_JARS;
    for profile in &profiles {
        if cancel.load(Ordering::Relaxed) || remaining == 0 {
            break;
        }
        let n = scan_profile_mods(
            profile,
            &catalog,
            &cancel,
            &processes,
            remaining,
            total_jars,
            &mut mods,
            &mut findings,
            &mut coverage,
            &mut diagnostics,
            &mut done,
            &mut bytes_hashed,
            &mut progress,
        );
        remaining = remaining.saturating_sub(n);
    }
    let mod_scan_partial = coverage.iter().any(|c| {
        c.check.starts_with("Mod file ")
            || c.check.starts_with("Archive ")
            || c.check.starts_with("Mod inventory")
    });
    coverage.push(Coverage::new(
        "Minecraft mod JAR analysis",
        if mod_scan_partial {
            CoverageStatus::Partial
        } else {
            CoverageStatus::Completed
        },
        format!(
            "Analyzed {} mod JAR(s); estimated bytes read={}.",
            mods.len(),
            bytes_hashed
        ),
    ));
    if !processes.iter().any(|p| p.confirmed_minecraft) {
        coverage.push(Coverage::new("Optional JVM class inspection",CoverageStatus::Skipped,"No confirmed Minecraft process was available for startup-agent correlation; no class inventory is claimed."));
    }
    coverage.push(Coverage::new("JVM launch arguments",CoverageStatus::Skipped,"The Rust milestone does not query process command lines. Agent state is established only by the PID- and creation-time-bound local rendezvous."));
    coverage.push(Coverage::new(
        "Java runtime version and architecture",
        CoverageStatus::Skipped,
        "Runtime PE/Java version identification is not implemented in this migration milestone.",
    ));
    coverage.push(Coverage::new("Authenticode verification",CoverageStatus::Skipped,"Authenticode verification is not implemented in this Rust milestone; unsigned status is not inferred."));
    coverage.push(Coverage::new("Doomsday-specific verified signatures",CoverageStatus::Partial,"The preserved v7.2 catalog has no verified Doomsday-specific hash, metadata ID, class/package identifier, or native module signature. No named Doomsday detection is claimed."));
    let canceled = cancel.load(Ordering::Relaxed);
    if canceled {
        coverage.push(Coverage::new("User cancellation",CoverageStatus::Partial,"The user stopped this scan. Results and reports cover work completed before cancellation."));
    }
    let out = report::choose_report_dir().map_err(|e| e.to_string())?;
    let report = ScanReport {
        schema_version: 1,
        scanner_version: "8.0.0".into(),
        scan_id: format!(
            "{}-{}-{}",
            started.format("%Y%m%d%H%M%S"),
            started.timestamp_subsec_nanos(),
            std::process::id()
        ),
        started_utc: started,
        completed_utc: Utc::now(),
        user: user_name(),
        profiles,
        processes,
        mods,
        findings,
        coverage,
        diagnostics,
        canceled,
        reports_directory: Some(out.clone()),
    };
    emit(
        &mut progress,
        92,
        "Correlate evidence",
        "Only exact catalogued hashes produce named positive findings",
    );
    let paths = report::write_reports(&report, &out).map_err(|e| e.to_string())?;
    for p in paths {
        tracing::info!(path=%p.display(),"report written");
    }
    if canceled {
        emit(
            &mut progress,
            99,
            "Canceled",
            "Partial scan reports written; remaining checks were not completed",
        );
    } else {
        emit(
            &mut progress,
            100,
            "Complete",
            "Scan and TXT/HTML/JSON/diagnostics reports finished",
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_profile_log_mod_ids_and_versions() {
        let root = std::env::temp_dir().join(format!("mc-scanner-log-{}", std::process::id()));
        let logs = root.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("latest.log"),
            "[main/INFO]: Loading 1 mods:\n[main/INFO]: - appleskin 3.0.10+mc26\n",
        )
        .unwrap();
        let p = crate::model::ProfileRecord {
            name: "fixture".into(),
            launcher: "test".into(),
            root: root.clone(),
            mods_dir: None,
            log_dir: Some(logs),
            evidence: "fixture".into(),
        };
        let ids = scan_log_mod_ids(&p);
        assert_eq!(
            ids.get("appleskin").map(String::as_str),
            Some("3.0.10+mc26")
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
