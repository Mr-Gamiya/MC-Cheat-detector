use crate::model::ProfileRecord;
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

fn push_profile(
    out: &mut Vec<ProfileRecord>,
    seen: &mut HashSet<PathBuf>,
    path: PathBuf,
    launcher: &str,
    evidence: &str,
) {
    let Ok(root) = fs::canonicalize(&path) else {
        return;
    };
    if !root.is_dir() || !seen.insert(root.clone()) {
        return;
    }
    let leaf = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("Minecraft")
        .to_owned();
    let mods = root.join("mods");
    let logs = root.join("logs");
    out.push(ProfileRecord {
        name: leaf,
        launcher: launcher.to_owned(),
        root,
        mods_dir: mods.is_dir().then_some(mods),
        log_dir: logs.is_dir().then_some(logs),
        evidence: evidence.to_owned(),
    });
}

fn instance_children(
    out: &mut Vec<ProfileRecord>,
    seen: &mut HashSet<PathBuf>,
    root: &Path,
    launcher: &str,
    limit: usize,
) {
    if !root.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten().take(limit) {
        let p = entry.path();
        if p.is_dir() {
            push_profile(out, seen, p, launcher, "launcher instance directory");
        }
    }
}

pub fn discover_profiles() -> (Vec<ProfileRecord>, Vec<String>) {
    let mut out = Vec::new();
    let mut diagnostics = Vec::new();
    let mut seen = HashSet::new();
    let roaming = env::var_os("APPDATA").map(PathBuf::from);
    let local = env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let user = env::var_os("USERPROFILE").map(PathBuf::from);

    if let Some(appdata) = &roaming {
        let mc = appdata.join(".minecraft");
        if mc.is_dir() {
            push_profile(
                &mut out,
                &mut seen,
                mc,
                "Official / Vanilla",
                "known current-user .minecraft directory",
            );
        }

        let official_config = appdata.join(".minecraft").join("launcher_profiles.json");
        if let Ok(text) = fs::read_to_string(&official_config) {
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(v) => {
                    if let Some(profiles) = v.get("profiles").and_then(|x| x.as_object()) {
                        for (name, profile) in profiles.iter().take(256) {
                            if let Some(dir) = profile.get("gameDir").and_then(|x| x.as_str()) {
                                let p = PathBuf::from(dir);
                                if p.is_dir() {
                                    push_profile(
                                        &mut out,
                                        &mut seen,
                                        p,
                                        "Official Launcher",
                                        &format!("launcher profile {name}"),
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => diagnostics.push(format!(
                    "Could not parse {}: {e}",
                    official_config.display()
                )),
            }
        }

        instance_children(
            &mut out,
            &mut seen,
            &appdata.join("ModrinthApp").join("profiles"),
            "Modrinth",
            512,
        );
        instance_children(
            &mut out,
            &mut seen,
            &appdata.join("PrismLauncher").join("instances"),
            "Prism Launcher",
            512,
        );
        instance_children(
            &mut out,
            &mut seen,
            &appdata.join("MultiMC").join("instances"),
            "MultiMC",
            512,
        );
        instance_children(
            &mut out,
            &mut seen,
            &appdata.join("ATLauncher").join("instances"),
            "ATLauncher",
            512,
        );
        instance_children(
            &mut out,
            &mut seen,
            &appdata
                .join("CurseForge")
                .join("Minecraft")
                .join("Instances"),
            "CurseForge",
            512,
        );
    }
    if let Some(local) = &local {
        instance_children(
            &mut out,
            &mut seen,
            &local.join("ModrinthApp").join("profiles"),
            "Modrinth",
            512,
        );
        instance_children(
            &mut out,
            &mut seen,
            &local
                .join("Programs")
                .join("PrismLauncher")
                .join("instances"),
            "Prism Launcher",
            512,
        );
        instance_children(
            &mut out,
            &mut seen,
            &local.join("CurseForge").join("Minecraft").join("Instances"),
            "CurseForge",
            512,
        );
    }
    if let Some(user) = &user {
        instance_children(
            &mut out,
            &mut seen,
            &user.join(".minecraft").join("instances"),
            "Custom",
            256,
        );
        instance_children(
            &mut out,
            &mut seen,
            &user.join("Games").join("Minecraft"),
            "Custom",
            256,
        );
        instance_children(
            &mut out,
            &mut seen,
            &user.join("Documents").join("Minecraft"),
            "Custom",
            128,
        );
    }

    // Search only known launcher/game roots for custom nested instances. Never
    // recurse through all of AppData or the entire user profile.
    let mut additional = 0usize;
    let mut visited = 0usize;
    let mut search_roots = Vec::new();
    if let Some(a) = &roaming {
        search_roots.extend([
            a.join("ModrinthApp"),
            a.join("PrismLauncher"),
            a.join("MultiMC"),
            a.join("ATLauncher"),
            a.join("CurseForge").join("Minecraft").join("Instances"),
        ]);
    }
    if let Some(a) = &local {
        search_roots.extend([
            a.join("ModrinthApp"),
            a.join("Programs").join("PrismLauncher"),
            a.join("CurseForge").join("Minecraft").join("Instances"),
        ]);
    }
    if let Some(u) = &user {
        search_roots.extend([
            u.join(".minecraft"),
            u.join("Games").join("Minecraft"),
            u.join("Documents").join("Minecraft"),
        ]);
    }
    'roots: for base in search_roots {
        if !base.is_dir() {
            continue;
        }
        for entry in WalkDir::new(base)
            .max_depth(4)
            .max_open(16)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            visited += 1;
            if visited > 20_000 {
                diagnostics.push(
                    "Custom-instance discovery stopped at the 20,000 directory-entry bound.".into(),
                );
                break 'roots;
            }
            if !entry.file_type().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name == "mods" && entry.path().parent().is_some() {
                if let Some(parent) = entry.path().parent() {
                    push_profile(
                        &mut out,
                        &mut seen,
                        parent.to_path_buf(),
                        "Discovered custom instance",
                        "mods directory under a known launcher root",
                    );
                    additional += 1;
                    if additional >= 1500 {
                        diagnostics
                            .push("Custom profile count reached its 1,500 profile bound.".into());
                        break 'roots;
                    }
                }
            }
        }
    }
    if out.is_empty() {
        diagnostics.push("No Minecraft profile directories were discovered under the current user's known launcher roots.".into());
    }
    (out, diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn does_not_return_duplicate_roots() {
        let mut out = vec![];
        let mut seen = HashSet::new();
        let p = env::temp_dir();
        push_profile(&mut out, &mut seen, p.clone(), "test", "one");
        push_profile(&mut out, &mut seen, p, "test", "two");
        assert!(out.len() <= 1);
    }
}
