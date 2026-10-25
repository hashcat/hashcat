fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let version = read_hashcat_version();
        let mut res = winresource::WindowsResource::new();
        if let Some(path) = find_windres() {
            res.set_windres_path(&path);
        }
        res.set("FileDescription", "hashcat dynamic hash bridge")
            .set("ProductName", "hashcat")
            .set("CompanyName", "hashcat")
            .set("LegalCopyright", "MIT License")
            .set("FileVersion", &version)
            .set("ProductVersion", &version);

        // The numeric version, which Explorer shows as the file version, would otherwise come from
        // the crate's own version in Cargo.toml.
        let packed = pack_version(&version);
        res.set_version_info(winresource::VersionInfo::FILEVERSION, packed)
            .set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed);
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

fn pack_version(version: &str) -> u64 {
    // Four 16 bit fields, major first, so "8.0.0" becomes 8.0.0.0.
    let mut packed: u64 = 0;
    for (i, part) in version.split('.').take(4).enumerate() {
        let field: u64 = part.parse().unwrap_or(0);
        packed |= (field & 0xffff) << (48 - (i * 16));
    }
    packed
}

fn read_hashcat_version() -> String {
    // A crate built from a release package has no src/Makefile three levels up. The version only
    // labels the DLL's Windows properties, so a missing Makefile gets the same fallback as a
    // Makefile without the line, rather than stopping the build.
    let makefile = match std::fs::read_to_string("../../../src/Makefile") {
        Ok(makefile) => makefile,
        Err(_) => return "0.0.0".to_string(),
    };
    for line in makefile.lines() {
        if line.starts_with("PRODUCTION_VERSION") {
            if let Some(v) = line.split(":=").nth(1) {
                return v.trim().trim_start_matches('v').to_string();
            }
        }
    }
    "0.0.0".to_string()
}
