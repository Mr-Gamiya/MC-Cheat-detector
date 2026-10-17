fn main() {
    println!("cargo:rerun-if-changed=../../signatures/signatures.json");
    println!("cargo:rerun-if-changed=../../assets/scanner.ico");
    println!("cargo:rerun-if-changed=../../assets/app.manifest");
    let manifest_dir = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.join("../..");
    let agent = workspace.join("target/embedded-agent/mc-jvmti-agent.dll");
    println!("cargo:rerun-if-changed={}", agent.display());
    let generated = if agent.is_file() {
        let path = agent.canonicalize().unwrap_or(agent.clone());
        let path = path
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("#[allow(dead_code)] pub const EMBEDDED_AGENT: Option<&'static [u8]> = Some(include_bytes!(\"{path}\"));\n")
    } else {
        "#[allow(dead_code)] pub const EMBEDDED_AGENT: Option<&'static [u8]> = None;\n".to_owned()
    };
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("embedded_agent.rs"), generated)
        .expect("write generated embedded-agent declaration");

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "Minecraft Cheat Scanner");
        res.set("FileDescription", "Local Minecraft integrity scanner");
        res.set("ProductVersion", "8.0.0");
        res.set("FileVersion", "8.0.0");
        let assets = manifest_dir.join("../../assets");
        let icon = assets.join("scanner.ico");
        let manifest = assets.join("app.manifest");
        if icon.is_file() {
            if let Some(path) = icon.to_str() {
                res.set_icon(path);
            }
        }
        if manifest.is_file() {
            if let Some(path) = manifest.to_str() {
                res.set_manifest_file(path);
            }
        }
        if let Err(e) = res.compile() {
            println!("cargo:warning=Windows version resources were not embedded: {e}");
        }
    }
}
