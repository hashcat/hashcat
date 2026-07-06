# hashcat Rust Plugin Quickstart

## Introduction

hashcat v7.1.2 introduces a new assimilation bridge plugin, the Rust
bridge, that allows you to write custom hash-matching algorithms in
Rust. This plugin system fits into the regular cracking workflow,
replacing or extending internal kernel routines.

When enabled, hashcat uses the plugin's `calc_hash()` function to
compute hash candidates. This makes it easy to experiment with new or
obscure algorithms without modifying core C code or writing
OpenCL/CUDA kernels.

This guide shows you how to quickly implement a custom algorithm in
Rust. You simply:

1. Write your logic in `calc_hash()`.
2. Build your plugin with `cargo build --release`.
3. Load it into hashcat and start cracking.

You can use any Rust crates you like.

## Quick Start

A benchmark is a simple way to verify that your setup works correctly.
hashcat mode `74000` is preconfigured to load a generic Rust plugin
from a dynamic library:

    hashcat -m 74000 -b

## Yescrypt in One Line

### Generate a Yescrypt Test Hash

    echo password | mkpasswd -s -m yescrypt --rounds 5

- `mkpasswd` is part of the `whois` package.
- `--rounds` can be any number from 1 to 11.

Example output:

    $y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0

### Prepare the Hash Line for hashcat

Take the full hash and append a `*` followed by the salt (settings)
portion to it. The appended settings must start and end with a `$`.

    $y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$

                settings
    /------------------------------\
    |                              |
     $y$j9T$uxVFACnNnGBakt9MLrpFf0$ SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0

### Plugin Code

Install Rust. If you’re on Windows, also ensure `rustup` is installed
and the Windows target is added to the Rust toolchain:

    rustup target add x86_64-pc-windows-gnu

If you encounter issues with your Rust installation, see
`hashcat-rust-plugin-requirements.md`.

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

and build the plugin:

    cd Rust/bridges/generic_hash
    cargo build --release

or, if you’re on Windows:

    cd Rust/bridges/generic_hash
    cargo build --release --target x86_64-pc-windows-gnu

That’s it.

### Benchmark

    hashcat -m 74000 yescrypt.hash -a 3 ?b?b?b?b?b?b?b

### Regular Cracking

    hashcat -m 74000 yescrypt.hash wordlist.txt
