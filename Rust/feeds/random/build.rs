fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let version = read_hashcat_version();
        let mut res = winresource::WindowsResource::new();
        if let Some(path) = find_windres() {
            res.set_windres_path(&path);
        }
        res.set("FileDescription", "hashcat random feed")
            .set("ProductName", "hashcat")
            .set("CompanyName", "hashcat")
            .set("LegalCopyright", "MIT License")
            .set("FileVersion", &version)
            .set("ProductVersion", &version);
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to embed VERSIONINFO: {e}");
        }
    }
}

fn find_windres() -> Option<String> {
    let target = std::env::var("TARGET").ok()?;
    let prefix = target.strip_suffix("-windows-gnu")?;
    let name = format!("{}-w64-mingw32-windres", prefix.replace("pc-", ""));
    std::process::Command::new("which")
        .arg(&name)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
}

fn read_hashcat_version() -> String {
    let makefile =
        std::fs::read_to_string("../../../src/Makefile").expect("Cannot read src/Makefile");
    for line in makefile.lines() {
        if line.starts_with("PRODUCTION_VERSION") {
            if let Some(v) = line.split(":=").nth(1) {
                return v.trim().trim_start_matches('v').to_string();
            }
        }
    }
    "0.0.0".to_string()
}
