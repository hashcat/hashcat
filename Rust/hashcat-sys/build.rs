use std::env;
use std::path::PathBuf;

fn main() {
    // The bindings go into OUT_DIR, which belongs to this build alone.
    //
    // They used to be written to src/bindings.rs, inside the shared source directory. The two
    // bridge crates that depend on this one are built by separate cargo invocations, and make runs
    // those in parallel, so one build script could rewrite that single file while the other crate
    // was compiling it. The result was an intermittent build failure reporting unresolved imports
    // from hashcat_sys, on a file that was simply half written at the moment it was read.

    println!("cargo:rerun-if-changed=src/hashcat_types.h");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");

    let out_path = PathBuf::from(out_dir).join("bindings.rs");

    // Allowlisted so the bindings are the same on every target and the crate
    // does not re-export the host's libc types.

    bindgen::Builder::default()
        .header("src/hashcat_types.h")
        .allowlist_type("u32")
        .allowlist_type("unit_t")
        .allowlist_type("hc_dynlib_t")
        .allowlist_type("salt_t")
        .allowlist_type("generic_io_tmp_t")
        .allowlist_type("generic_io_t")
        .allowlist_type("bridge_context_t")
        .allowlist_type("RS_.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&out_path)
        .expect("Couldn't write bindings!");
}
