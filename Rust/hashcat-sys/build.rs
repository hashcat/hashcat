fn main() {
    let bindings = "src/bindings.rs";

    if !std::path::Path::new(bindings).exists() {
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
            .write_to_file(bindings)
            .expect("Couldn't write bindings!");
    }
}
