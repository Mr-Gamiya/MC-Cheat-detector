use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    path::Path,
};
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct Catalog {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "catalogVersion")]
    pub catalog_version: String,
    #[serde(default)]
    pub entries: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureEntry {
    pub sha256: String,
    pub label: String,
    pub project: String,
    pub status: String,
    pub source: String,
    pub evidence: String,
    #[serde(rename = "artifactType", default)]
    pub artifact_type: String,
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog read failed: {0}")]
    Io(#[from] io::Error),
    #[error("catalog JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported signature catalog schema {0}")]
    Schema(u32),
    #[error("invalid SHA-256 value for signature {0}")]
    InvalidDigest(String),
    #[error("duplicate signature digest {0}")]
    Duplicate(String),
}

impl Catalog {
    pub fn load(path: &Path) -> Result<Self, CatalogError> {
        let mut text = String::new();
        File::open(path)?.read_to_string(&mut text)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, CatalogError> {
        let catalog: Self = serde_json::from_str(text)?;
        if catalog.schema_version != 2 {
            return Err(CatalogError::Schema(catalog.schema_version));
        }
        let mut seen = HashMap::new();
        for item in &catalog.entries {
            let digest = item.sha256.to_ascii_lowercase();
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(CatalogError::InvalidDigest(item.label.clone()));
            }
            if seen.insert(digest.clone(), ()).is_some() {
                return Err(CatalogError::Duplicate(digest));
            }
            if item.project.trim().is_empty()
                || item.source.trim().is_empty()
                || item.evidence.trim().is_empty()
            {
                return Err(CatalogError::InvalidDigest(item.label.clone()));
            }
        }
        Ok(catalog)
    }

    pub fn exact_verified_match(
        &self,
        digest: &str,
        artifact_type: &str,
    ) -> Option<&SignatureEntry> {
        self.entries.iter().find(|entry| {
            entry.sha256.eq_ignore_ascii_case(digest)
                && entry.artifact_type.eq_ignore_ascii_case(artifact_type)
                && matches!(
                    entry.status.as_str(),
                    "OfficialSourceHashed" | "IndependentlyVerified"
                )
        })
    }
}

pub fn sha256_file(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    let length = before.len();
    let modified = before.modified().ok();
    if length > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds hashing limit",
        ));
    }
    let mut hash = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut read_total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read_total += n as u64;
        if read_total > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file grew beyond hashing limit",
            ));
        }
        hash.update(&buf[..n]);
    }
    let after = file.metadata()?;
    if after.len() != length || (modified.is_some() && after.modified().ok() != modified) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "file changed while hashing",
        ));
    }
    if let Ok(path_after) = std::fs::metadata(path) {
        if path_after.len() != length
            || (modified.is_some() && path_after.modified().ok() != modified)
        {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "file path changed while hashing",
            ));
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_is_stable_and_hex() {
        let mut h = Sha256::new();
        h.update(b"test fixture");
        let digest = format!("{:x}", h.finalize());
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    #[test]
    fn unknown_digest_is_not_a_match() {
        let catalog = Catalog {
            schema_version: 2,
            catalog_version: "fixture".into(),
            entries: vec![],
        };
        assert!(catalog
            .exact_verified_match(&"0".repeat(64), "JAR")
            .is_none());
    }
    #[test]
    fn preserves_current_catalog_and_detects_duplicates() {
        let source = include_str!("../../../signatures/signatures.json");
        let catalog = Catalog::parse(source).unwrap();
        assert_eq!(catalog.schema_version, 2);
        assert_eq!(catalog.entries.len(), 6);
        let duplicate=format!("{{\"schemaVersion\":2,\"catalogVersion\":\"test\",\"entries\":[{{\"sha256\":\"{}\",\"label\":\"a\",\"project\":\"x\",\"status\":\"IndependentlyVerified\",\"source\":\"source\",\"evidence\":\"fixture\",\"artifactType\":\"JAR\"}},{{\"sha256\":\"{}\",\"label\":\"b\",\"project\":\"x\",\"status\":\"IndependentlyVerified\",\"source\":\"source\",\"evidence\":\"fixture\",\"artifactType\":\"JAR\"}}]}}","a".repeat(64),"a".repeat(64));
        assert!(matches!(
            Catalog::parse(&duplicate),
            Err(CatalogError::Duplicate(_))
        ));
    }
    #[test]
    fn only_provenance_bearing_verified_statuses_match() {
        let e = SignatureEntry {
            sha256: "a".repeat(64),
            label: "Fixture release".into(),
            project: "Fixture Client".into(),
            status: "IndependentlyVerified".into(),
            source: "https://example.invalid/release".into(),
            evidence: "synthetic test record".into(),
            artifact_type: "JAR".into(),
        };
        let c = Catalog {
            schema_version: 2,
            catalog_version: "fixture".into(),
            entries: vec![e.clone()],
        };
        assert!(c.exact_verified_match(&e.sha256, "JAR").is_some());
        assert!(c.exact_verified_match(&e.sha256, "DLL").is_none());
        let mut weak = e;
        weak.status = "Experimental".into();
        let c = Catalog {
            schema_version: 2,
            catalog_version: "fixture".into(),
            entries: vec![weak.clone()],
        };
        assert!(c.exact_verified_match(&weak.sha256, "JAR").is_none());
    }
}
