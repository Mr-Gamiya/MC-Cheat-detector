use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub check: String,
    pub status: CoverageStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Completed,
    Partial,
    Skipped,
    Restricted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub client_name: String,
    pub category: String,
    pub evidence_type: String,
    pub detection_method: String,
    pub confidence: String,
    pub path: Option<PathBuf>,
    pub sha256: Option<String>,
    pub process_id: Option<u32>,
    pub profile: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub limitations: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub name: String,
    pub path: Option<PathBuf>,
    pub base_address: Option<usize>,
    pub size_bytes: Option<u32>,
    pub file_exists: bool,
    pub sha256: Option<String>,
    pub signature_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub name: String,
    pub executable: Option<PathBuf>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub created_utc: Option<DateTime<Utc>>,
    pub creation_filetime: Option<u64>,
    pub owner: Option<String>,
    pub owner_status: String,
    pub confirmed_minecraft: bool,
    pub identification_methods: Vec<String>,
    pub profile: Option<String>,
    pub profile_path: Option<PathBuf>,
    pub modules: Vec<ModuleRecord>,
    pub module_status: String,
    pub jvm_agent_status: String,
    pub loaded_class_count: usize,
    pub loaded_class_names: Vec<String>,
    pub classloader_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModRecord {
    pub path: PathBuf,
    pub profile: String,
    pub sha256: Option<String>,
    pub metadata_id: Option<String>,
    pub metadata_name: Option<String>,
    pub version: Option<String>,
    pub loader: Option<String>,
    pub authenticity: String,
    pub runtime_log_listed: bool,
    pub runtime_log_version_match: Option<bool>,
    pub associated_process_id: Option<u32>,
    pub runtime_association: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub name: String,
    pub launcher: String,
    pub root: PathBuf,
    pub mods_dir: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub scanner_version: String,
    pub scan_id: String,
    pub started_utc: DateTime<Utc>,
    pub completed_utc: DateTime<Utc>,
    pub user: String,
    pub profiles: Vec<ProfileRecord>,
    pub processes: Vec<ProcessRecord>,
    pub mods: Vec<ModRecord>,
    /// Named detections only. The engine inserts entries here only for exact
    /// verified signature matches; weak leads belong in diagnostics/coverage.
    pub findings: Vec<Finding>,
    pub coverage: Vec<Coverage>,
    pub diagnostics: Vec<String>,
    pub canceled: bool,
    pub reports_directory: Option<PathBuf>,
}

impl Coverage {
    pub fn new(
        check: impl Into<String>,
        status: CoverageStatus,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            check: check.into(),
            status,
            detail: detail.into(),
        }
    }
}
