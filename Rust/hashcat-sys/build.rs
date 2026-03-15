fn main() {
    let bindings = "src/bindings.rs";

    if !std::path::Path::new(bindings).exists() {
        bindgen::Builder::default()
            .header("src/hashcat_types.h")
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(bindings)
            .expect("Couldn't write bindings!");
    }
}
