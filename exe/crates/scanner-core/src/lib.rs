//! Read-only Minecraft scanner engine. Platform inspection is best-effort and
//! every unavailable check is retained in `ScanReport.coverage`.
pub mod archive;
pub mod discovery;
pub mod model;
pub mod process;
pub mod report;
pub mod runtime_correlation;
pub mod scan;
pub mod signatures;

pub use model::{Coverage, CoverageStatus, Finding, ProcessRecord, ScanReport};
pub use scan::{run_scan, ScanEvent};
