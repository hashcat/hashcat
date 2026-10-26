# hashcat Rust Plugin Quickstart

## Introduction

Mode 74000 uses the Rust assimilation bridge to run custom hash-matching algorithms written in Rust. The bridge fits into the regular cracking workflow by replacing or extending internal kernel routines.

hashcat calls the plugin's `calc_hash()` function to compute candidate hashes. This makes it possible to experiment with new or uncommon algorithms without modifying the core C code or writing OpenCL or CUDA kernels.

To implement a custom algorithm in Rust:

1. Write your logic in `calc_hash()`.
2. Build your plugin with `cargo build --release`.
3. Load it into hashcat and start cracking.

You can use any Rust crates you like.

## Quick Start

A benchmark is a simple way to verify the setup. Mode `74000` is configured to load the generic Rust plugin from a dynamic library:

    hashcat -m 74000 -b

## Yescrypt in One Line

### Generate a Yescrypt Test Hash

    echo password | mkpasswd -s -m yescrypt --rounds 5

- `mkpasswd` is part of the `whois` package.
- `--rounds` can be any number from 1 to 11.

Example output:

    $y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0

### Prepare the hash line for hashcat

Take the full hash and append a `*` followed by the salt (settings) portion to it. The appended settings must start and end with a `$`.

    $y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$

                settings
    /------------------------------\
    |                              |
     $y$j9T$uxVFACnNnGBakt9MLrpFf0$ SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0

### Plugin Code

Install Rust. On Windows, also ensure that `rustup` is installed and add the Windows target to the Rust toolchain:

    rustup target add x86_64-pc-windows-gnu

If you encounter issues with your Rust installation, see `hashcat-rust-plugin-requirements.md`.

Next, add the required crate to the dependencies:

    cd Rust/bridges/generic_hash
    cargo add yescrypt-mcf --git https://git.launchpad.net/yescrypt-mcf --tag v0.1.0

Then edit `Rust/bridges/generic_hash/src/generic_hash.rs`:

```rust
// Trailing zeroes are necessary.
#[unsafe(no_mangle)]
pub static ST_HASH: &[u8] =
    b"$y$j9T$4Tf53qrQ.mIct2X0SZjdR.$39KwVEoHqORaU3IfDBz82I1hH1sabyNU7xMngDOiad9*$y$j9T$4Tf53qrQ.mIct2X0SZjdR.$\0";
#[unsafe(no_mangle)]
pub static ST_PASS: &[u8] = b"password\0";

pub(crate) fn calc_hash(password: &[u8], salt: &[u8]) -> Vec<String> {
    if let Ok(digest) = yescrypt_mcf::generate_hash(password, salt) {
        vec![digest]
    } else {
        vec![]
    }
}
```

Then build the plugin:

    cd Rust/bridges/generic_hash
    cargo build --release

On Windows, build it for the Windows target:

    cd Rust/bridges/generic_hash
    cargo build --release --target x86_64-pc-windows-gnu

### Mask Attack

    hashcat -m 74000 yescrypt.hash -a 3 ?b?b?b?b?b?b?b

### Wordlist Attack

    hashcat -m 74000 yescrypt.hash wordlist.txt
