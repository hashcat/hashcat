use std::env;

fn main() {
    if env::var("REGENERATE_BINDINGS").is_ok() {
        bindgen::Builder::default()
            .header("src/hashcat_types.h")
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("src/bindings.rs")
            .expect("Couldn't write bindings!");
    }
}
