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

    bindgen::Builder::default()
        .header("src/hashcat_types.h")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&out_path)
        .expect("Couldn't write bindings!");
}
