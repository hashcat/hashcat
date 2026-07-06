# hashcat Rust Plugin Requirements

This document explains how to build and use the hashcat Rust plugin on
Linux, Windows, and macOS.

## Linux

1. **Install Rust**

   Rust **1.88 or newer** is recommended. Older versions may not work
   reliably.

2. **Build hashcat**

   If you are building hashcat from source, run:

   ```
   make linux
   ```

   This should build the Rust bridge and the default plugin
   automatically. To verify, run:

   ```
   ./hashcat.bin -m 74000 -b
   ```

3. **Customize the plugin**

   Edit `Rust/bridges/generic_hash/src/generic_hash.rs` to fit your needs.
   Typically, you only need to adjust:

   - `ST_HASH`
   - `ST_PASS`
   - The `calc_hash` function

   You can also add unit tests before building. Run them with `cargo test`.

4. **Build the customized plugin**

   ```
   cd Rust/bridges/generic_hash
   cargo build --release
   ```

   This produces `libgeneric_hash.so` in `Rust/bridges/generic_hash/target/release`.

5. **Run hashcat**

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

   Ensure both `cargo` and `rustup` are installed. If Rust was
   installed via `rustup`, you already have them.  Prefer **Rust 1.88
   or newer**.

2. **Build hashcat**

   You only have to do this if you're building from sources.

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

   Optionally, add unit tests and run then with `cargo test`.

4. **Build the customized plugin**

   Add a Windows target to the Rust toolchain (you only have to do
   this once):

   ```
   rustup target add x86_64-pc-windows-gnu
   ```

   Then:

   ```
   cd Rust/bridges/generic_hash
   cargo build --release --target x86_64-pc-windows-gnu
   ```

   This produces `generic_hash.dll` in
   `Rust/bridges/generic_hash/target/x86_64-pc-windows-gnu/release`.

5. **Run hashcat**

   ```
   hashcat -a 0 -m 74000 hashfile wordlist
   ```

   If you moved or renamed `generic_hash.dll`, specify it with:

   ```
   --bridge-parameter1 /path/to/generic_hash.dll
   ```

## macOS

hashcat does not ship prebuilt macOS binaries, so you must build both
the bridge and the plugin yourself.

1. Follow the same steps as in the **Linux** section.
2. On macOS, Rust produces `.dylib` files. After building a customized
   plugin with `cargo build --release`, either:
   - Rename:
     ```
     mv Rust/bridges/generic_hash/target/release/libgeneric_hash.dylib \
        Rust/bridges/generic_hash/target/release/libgeneric_hash.so
     ```
   - Or run hashcat with:
     ```
     --bridge-parameter1 /path/to/libgeneric_hash.dylib
     ```
