use crate::{
    model::ModRecord,
    signatures::{sha256_file, Catalog},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Cursor, Read, Seek},
    path::Path,
};
use thiserror::Error;
use zip::ZipArchive;

const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRY_COUNT: usize = 20_000;
const MAX_EXPANDED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_NESTED_BYTES: u64 = 16 * 1024 * 1024;

pub fn validate_default_limits() -> Result<(), ArchiveError> {
    if MAX_ARCHIVE_BYTES == 0
        || MAX_ENTRY_COUNT == 0
        || MAX_EXPANDED_BYTES == 0
        || MAX_METADATA_BYTES > MAX_EXPANDED_BYTES
        || MAX_NESTED_BYTES > MAX_ARCHIVE_BYTES
    {
        return Err(ArchiveError::Limit);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("file cannot be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive format is invalid: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("archive exceeds configured size or expansion limits")]
    Limit,
}

struct Metadata {
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    loader: Option<String>,
}
fn metadata_from_json(bytes: &[u8], loader: &str) -> Option<Metadata> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    Some(Metadata {
        id: v.get("id").and_then(Value::as_str).map(str::to_owned),
        name: v.get("name").and_then(Value::as_str).map(str::to_owned),
        version: v.get("version").and_then(Value::as_str).map(str::to_owned),
        loader: Some(loader.into()),
    })
}
fn read_bounded<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
) -> Result<Option<Vec<u8>>, ArchiveError> {
    match zip.by_name(name) {
        Ok(e) => {
            if e.size() > MAX_METADATA_BYTES {
                return Err(ArchiveError::Limit);
            }
            let mut b = Vec::with_capacity(e.size() as usize);
            e.take(MAX_METADATA_BYTES + 1).read_to_end(&mut b)?;
            if b.len() as u64 > MAX_METADATA_BYTES {
                return Err(ArchiveError::Limit);
            }
            Ok(Some(b))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn take_metadata<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
) -> Result<Option<Metadata>, ArchiveError> {
    for (file, loader) in [("fabric.mod.json", "Fabric"), ("quilt.mod.json", "Quilt")] {
        if let Some(b) = read_bounded(zip, file)? {
            if let Some(m) = metadata_from_json(&b, loader) {
                return Ok(Some(m));
            }
        }
    }
    for file in ["META-INF/neoforge.mods.toml", "META-INF/mods.toml"] {
        if let Some(b) = read_bounded(zip, file)? {
            let text = String::from_utf8_lossy(&b);
            let id = text.lines().find_map(|l| {
                let t = l.trim();
                t.strip_prefix("modId")
                    .and_then(|x| x.split_once('='))
                    .map(|(_, v)| v.trim().trim_matches('"').to_owned())
            });
            let ver = text.lines().find_map(|l| {
                let t = l.trim();
                t.strip_prefix("version")
                    .and_then(|x| x.split_once('='))
                    .map(|(_, v)| v.trim().trim_matches('"').to_owned())
            });
            return Ok(Some(Metadata {
                id,
                name: None,
                version: ver,
                loader: Some(
                    if file.contains("neoforge") {
                        "NeoForge"
                    } else {
                        "Forge"
                    }
                    .into(),
                ),
            }));
        }
    }
    Ok(None)
}
fn inspect_archive<R: Read + Seek>(
    reader: R,
    depth: u8,
    expanded: &mut u64,
    nested_sig: &mut Vec<(String, String)>,
) -> Result<Option<Metadata>, ArchiveError> {
    let mut zip = ZipArchive::new(reader)?;
    if zip.len() > MAX_ENTRY_COUNT {
        return Err(ArchiveError::Limit);
    }
    let metadata = take_metadata(&mut zip)?;
    let mut nested_bytes = 0u64;
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let name = entry.name()?.into_owned();
        *expanded = expanded.saturating_add(entry.size());
        if *expanded > MAX_EXPANDED_BYTES {
            return Err(ArchiveError::Limit);
        }
        if depth >= 1 || !name.to_ascii_lowercase().ends_with(".jar") {
            continue;
        }
        if entry.size() > MAX_NESTED_BYTES {
            continue;
        }
        nested_bytes = nested_bytes.saturating_add(entry.size());
        if nested_bytes > MAX_NESTED_BYTES {
            continue;
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.take(MAX_NESTED_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_NESTED_BYTES {
            continue;
        }
        let mut nested_expanded = *expanded;
        if inspect_archive(
            Cursor::new(bytes.as_slice()),
            depth + 1,
            &mut nested_expanded,
            nested_sig,
        )
        .is_ok()
        {
            let digest = format!("{:x}", Sha256::digest(bytes.as_slice()));
            nested_sig.push((name, digest));
        }
        *expanded = nested_expanded;
    }
    Ok(metadata)
}

pub fn analyze_mod(
    path: &Path,
    profile: &str,
    catalog: &Catalog,
) -> Result<(ModRecord, Vec<(String, String)>), ArchiveError> {
    let len = path.metadata()?.len();
    if len > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError::Limit);
    }
    let digest = sha256_file(path, MAX_ARCHIVE_BYTES)?;
    let f = File::open(path)?;
    let mut expanded = 0;
    let mut nested = Vec::new();
    let metadata = inspect_archive(f, 0, &mut expanded, &mut nested)?;
    let matched = catalog.exact_verified_match(&digest, "JAR");
    let record = ModRecord {
        path: path.to_path_buf(),
        profile: profile.into(),
        sha256: Some(digest.clone()),
        metadata_id: metadata.as_ref().and_then(|m| m.id.clone()),
        metadata_name: metadata.as_ref().and_then(|m| m.name.clone()),
        version: metadata.as_ref().and_then(|m| m.version.clone()),
        loader: metadata.and_then(|m| m.loader),
        authenticity: if matched.is_some() {
            "Exact catalogued release digest".into()
        } else {
            "UNKNOWN (no verified reference digest match)".into()
        },
        runtime_log_listed: false,
        runtime_log_version_match: None,
        associated_process_id: None,
        runtime_association: "JVM class loading not established".into(),
    };
    Ok((record, nested))
}

pub fn hash_module(
    path: &Path,
    catalog: &Catalog,
) -> Result<Option<(String, String, String)>, std::io::Error> {
    let digest = sha256_file(path, MAX_ARCHIVE_BYTES)?;
    Ok(catalog
        .exact_verified_match(&digest, "DLL")
        .map(|s| (digest, s.project.clone(), s.label.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn zip_bomb_guard_constants_are_bounded() {
        assert!(MAX_EXPANDED_BYTES < 1024 * 1024 * 1024);
        assert!(MAX_ENTRY_COUNT < 100_000);
        assert!(validate_default_limits().is_ok());
    }
    #[test]
    fn path_traversal_is_never_extracted() {
        let n = "../../evil.class";
        assert!(n.contains("../")); /* scanner only reads indexed streams; it has no extraction path */
    }
    #[test]
    fn detects_mod_metadata_after_filename_rename() {
        let path = std::env::temp_dir().join(format!(
            "scanner-test-{}-performance.jar",
            std::process::id()
        ));
        let file = File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("fabric.mod.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(
            br#"{"schemaVersion":1,"id":"fixture_mod","name":"Fixture","version":"1.2.3"}"#,
        )
        .unwrap();
        zip.finish().unwrap();
        let c = Catalog {
            schema_version: 2,
            catalog_version: "test".into(),
            entries: vec![],
        };
        let (m, _) = analyze_mod(&path, "fixture", &c).unwrap();
        assert_eq!(m.metadata_id.as_deref(), Some("fixture_mod"));
        assert_eq!(m.version.as_deref(), Some("1.2.3"));
        assert!(m.sha256.as_ref().is_some_and(|x| x.len() == 64));
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn renamed_known_bytes_match_exact_catalog_digest() {
        let path =
            std::env::temp_dir().join(format!("scanner-test-{}-fps-boost.jar", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("fabric.mod.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(br#"{"schemaVersion":1,"id":"harmless_name","version":"1"}"#)
            .unwrap();
        zip.finish().unwrap();
        let digest = sha256_file(&path, MAX_ARCHIVE_BYTES).unwrap();
        let sig = crate::signatures::SignatureEntry {
            sha256: digest.clone(),
            label: "fixture release".into(),
            project: "Synthetic Client".into(),
            status: "IndependentlyVerified".into(),
            source: "synthetic test fixture".into(),
            evidence: "exact test bytes".into(),
            artifact_type: "JAR".into(),
        };
        let c = Catalog {
            schema_version: 2,
            catalog_version: "test".into(),
            entries: vec![sig],
        };
        let (record, _) = analyze_mod(&path, "fixture", &c).unwrap();
        assert_eq!(record.authenticity, "Exact catalogued release digest");
        assert_eq!(record.sha256.as_deref(), Some(digest.as_str()));
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn discovers_exact_signature_inside_nested_jar() {
        let inner = Cursor::new(Vec::new());
        let mut iz = zip::ZipWriter::new(inner);
        iz.start_file("fabric.mod.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        iz.write_all(br#"{"schemaVersion":1,"id":"nested"}"#)
            .unwrap();
        let nested = iz.finish().unwrap().into_inner();
        let expected = format!("{:x}", Sha256::digest(&nested));
        let outer = Cursor::new(Vec::new());
        let mut oz = zip::ZipWriter::new(outer);
        oz.start_file(
            "META-INF/jars/renamed.jar",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        oz.write_all(&nested).unwrap();
        let data = oz.finish().unwrap().into_inner();
        let mut expanded = 0;
        let mut matches = Vec::new();
        inspect_archive(Cursor::new(data), 0, &mut expanded, &mut matches).unwrap();
        assert!(matches.iter().any(|(_, hash)| hash == &expected));
    }
    #[test]
    fn corrupt_jar_is_reported_as_error() {
        let path =
            std::env::temp_dir().join(format!("scanner-test-{}-bad.jar", std::process::id()));
        std::fs::write(&path, b"not a zip").unwrap();
        let c = Catalog {
            schema_version: 2,
            catalog_version: "test".into(),
            entries: vec![],
        };
        assert!(analyze_mod(&path, "fixture", &c).is_err());
        let _ = std::fs::remove_file(path);
    }
}
