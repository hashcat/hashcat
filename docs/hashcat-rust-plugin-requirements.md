# hashcat Rust Plugin Requirements

This document explains how to build and use the hashcat Rust plugin on Linux, Windows and macOS.

## Linux

1. **Install Rust**

   Rust **1.85 or newer** is required. The crates use Rust edition 2024, which Cargo supports from version 1.85. Earlier versions cannot parse their `Cargo.toml` files. The build checks the installed version and reports when it is too old.

   This version is newer than the packages in some distributions. Ubuntu 24.04 ships 1.75, for instance, so install Rust through `rustup` rather than the package manager.

2. **Install libclang**

   The `hashcat-sys` crate generates its bindings with `bindgen`, which loads `libclang` at build time. Distributions commonly package this library separately from the Clang compiler, so installing Rust alone is not sufficient.

   ```
   sudo apt install libclang-dev        # Debian, Ubuntu
   sudo pacman -S clang                 # Arch
   sudo dnf install clang-devel         # Fedora, RHEL
   ```

   Without it the build stops with:

   ```
   Unable to find libclang: "couldn't find any valid shared libraries matching:
   ['libclang.so', 'libclang-*.so', 'libclang.so.*', 'libclang-*.so.*'] ..."
   ```

   If the library is outside the paths searched by `bindgen`, specify its location with `LIBCLANG_PATH`.

3. **Build hashcat**

   To build hashcat from source, run:

   ```
   make linux
   ```

   This builds the Rust bridge and default plugin automatically. To verify, run:

   ```
   ./hashcat.bin -m 74000 -b
   ```

4. **Customize the plugin**

   Edit `Rust/bridges/generic_hash/src/generic_hash.rs` to fit your needs. Typically, you only need to adjust:

   - `ST_HASH`
   - `ST_PASS`
   - The `calc_hash` function

   You can also add unit tests before building. Run them with `cargo test`.

5. **Build the customized plugin**

   ```
   cd Rust/bridges/generic_hash
   cargo build --release
   ```

   This produces `libgeneric_hash.so` in `Rust/bridges/generic_hash/target/release`.

6. **Run hashcat**

   ```
   hashcat -a 0 -m 74000 hashfile wordlist
   ```

   (Add rules or use another attack mode as needed.)

   If you moved or renamed `libgeneric_hash.so`, specify it with:

   ```
   --bridge-parameter1 /path/to/libgeneric_hash.so
   ```

## Windows

1. **Install Rust**

   Ensure both `cargo` and `rustup` are installed. If Rust was installed via `rustup`, you already have them. **Rust 1.85 or newer** is required, for the reason given in the Linux section.

   The Windows binaries are cross-compiled from WSL, so `libclang` has to be installed on the WSL side too. See step 2 of the Linux section.

2. **Build hashcat**

   This step is required only when building hashcat from source.

   From a WSL shell, run:

   ```
   make win
   ```

   To confirm the bridge was built, run:

   ```
   hashcat -m 74000 -b
   ```

3. **Customize the plugin**

   Edit `Rust/bridges/generic_hash/src/generic_hash.rs`, modifying:

   - `ST_HASH`
   - `ST_PASS`
   - The `calc_hash` function

   Optionally, add unit tests and run them with `cargo test`.

4. **Build the customized plugin**

   Add a Windows target to the Rust toolchain (you only have to do this once):

   ```
   rustup target add x86_64-pc-windows-gnu
   ```

   Then:

   ```
   cd Rust/bridges/generic_hash
   cargo build --release --target x86_64-pc-windows-gnu
   ```

   This produces `generic_hash.dll` in `Rust/bridges/generic_hash/target/x86_64-pc-windows-gnu/release`.

5. **Run hashcat**

   ```
   hashcat -a 0 -m 74000 hashfile wordlist
   ```

   If you moved or renamed `generic_hash.dll`, specify it with:

   ```
   --bridge-parameter1 /path/to/generic_hash.dll
   ```

## macOS

hashcat does not provide prebuilt macOS binaries, so both the bridge and plugin must be built locally.

1. Follow the same steps as in the **Linux** section.
2. On macOS, Rust produces `.dylib` files. After building a customized plugin with `cargo build --release`, either:
   - Rename:
     ```
     mv Rust/bridges/generic_hash/target/release/libgeneric_hash.dylib \
        Rust/bridges/generic_hash/target/release/libgeneric_hash.so
     ```
   - Or run hashcat with:
     ```
     --bridge-parameter1 /path/to/libgeneric_hash.dylib
     ```
