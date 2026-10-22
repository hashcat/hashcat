# Compression libraries

hashcat reads compressed wordlists, hash lists and rule files through external libraries. It neither includes nor links against their code. Each library is loaded when its format is first used, so hashcat starts and runs normally on a system where none are installed.

| format | libraries tried in order | project |
| --- | --- | --- |
| `.gz` | `libz.so.1`, `libz.so` / `zlib1.dll`, `libz.dll`, `zlib.dll` | zlib |
| `.xz`, `.lzma` | `liblzma.so.5`, `liblzma.so` / `liblzma.dll`, `liblzma-5.dll` | XZ Utils |
| `.zst` | `libzstd.so.1`, `libzstd.so` / `libzstd.dll`, `zstd.dll` | Zstandard |

On macOS the names are `libz.1.dylib`, `liblzma.5.dylib` and `libzstd.1.dylib`.

Opening a `.zst` file without libzstd produces an error that lists every library name hashcat tried and the package to install. Other formats are unaffected. A `.gz` file still opens on a system that has zlib but not libzstd.

## Features that require a compression library

Two features require a compression library even when the command line names no compressed input file.

The shipped Markov statistics file, `hashcat.hcstat2`, is compressed with LZMA2. It expands to 128 MiB from 235 KiB, and no uncompressed copy is included. Every attack that traverses a mask therefore loads liblzma at startup. This includes `-a 1`, `-a 3`, `-a 6`, `-a 7`, `-a 12` and `--benchmark`, which uses `-a 3`.

Without liblzma, these commands fail at startup with an error naming the file and required library. Attack modes 0, 4, 5, 8 and 9 do not load the statistics table and are unaffected.

7-Zip hashes, `-m 11600`, carry the compressed data inside the hash line and hashcat decompresses it to verify a candidate. Which library that needs depends on how the archive was written: liblzma for an LZMA1 or LZMA2 archive, zlib for a DEFLATE one.

Both libraries were previously compiled into hashcat. A system that supported these features in an earlier release may now require an additional runtime package.

## Seeking inside a compressed wordlist

hashcat does not necessarily read a wordlist from beginning to end. Each device processes a different range of the keyspace, while a restored session or a run using `--skip` can begin in the middle. hashcat must therefore seek to a wordlist line by number.

A plain wordlist can seek directly to a byte offset. In a compressed stream, the decoded content at a position depends on everything before it. Reaching line ten million can therefore require decoding and discarding every preceding line. Each device pays that cost independently, so a run on eight GPUs can decode the same prefix eight times before trying its first candidate.

A wordlist compressed into independent pieces avoids this problem. A `.zst` file can contain multiple frames and an `.xz` file multiple blocks, each of which can be decoded without reading the preceding pieces. hashcat can begin with the piece containing the requested line and continue from there.

The first read records the location of each piece in the same seek database used for line offsets. Later runs reuse that index.

### xz

By default, `xz` writes the entire file as one block. When configured to use multiple threads, it writes one block per chunk:

    xz -T0 wordlist

This is the same option commonly used to improve compression speed, so an `.xz` file created on a multicore system is often already seekable. Option `--block-size` sets the granularity directly, and a smaller block means less to walk through after a seek:

    xz -T0 --block-size=8MiB wordlist

An `.xz` file stores its block index at the end, allowing hashcat to read the offsets directly. Concatenated `.xz` files are handled too: the index covers every block in the file, whichever stream it belongs to.

### zstd

Tool `zstd` writes one frame for the whole file, even with `-T0`. `pzstd`, which ships with Zstandard, writes one frame per chunk:

    pzstd -p 8 wordlist

The compression level determines the chunk size, while `-p` controls only the writing speed. The resulting wordlist contains frames every few megabytes regardless of its total size. Concatenating `.zst` files with `cat` works as well.

### gzip

A `.gz` file has no independent pieces and must be read from the beginning. Convert a gzip wordlist to `.xz` or `.zst` when the attack needs to seek.

### What hashcat reports

While building the index, hashcat warns once when a large compressed wordlist contains no seekable pieces. The warning names a tool that can create a seekable replacement.

These file formats are not specific to hashcat. `unxz` and `zstd -d` decompress them, and so does anything else that reads the format.

## Linux and the BSDs

These libraries are commonly installed as dependencies of other software. If one is missing, install its runtime package rather than its development package:

    Debian, Ubuntu    zlib1g        liblzma5      libzstd1
    Fedora, RHEL      zlib          xz-libs       libzstd
    Arch              zlib          xz            zstd

## macOS

    brew install zlib xz zstd

## Windows

Windows includes none of these libraries. **The official hashcat package includes all three** in the directory containing `hashcat.exe`, so no separate download, installation or registration is required. They are built from pinned upstream sources in the release build image, and the version that went into a package is recorded in the file that built it.

Replacing one of them with a newer build is supported, and is the way to pick up a security fix without waiting for a hashcat release. Keep the file name the same and leave it next to `hashcat.exe`.

The remainder of this section applies to a locally built Windows copy of hashcat, which includes none of these libraries. The folder holding `hashcat.exe` is searched first, and hashcat removes the current working directory from the DLL search path. `PATH` remains in the standard Windows search order, but placing the DLL next to `hashcat.exe` is the predictable choice. Two of the three projects publish a Windows build themselves:

**xz**, for `.xz` files. From https://github.com/tukaani-project/xz/releases take the `xz-<version>-windows.zip` and copy `bin_x86-64\liblzma.dll` next to `hashcat.exe`. The release is signed, and the `.sig` file beside it can be checked if you want to.

**Zstandard**, for `.zst` files. From https://github.com/facebook/zstd/releases take the `zstd-v<version>-win64.zip` and copy `dll\libzstd.dll` next to `hashcat.exe`.

Neither file requires installation or registration. Copying it into the hashcat directory makes it available.

**A local build requires a trusted zlib DLL for `.gz` files.** The zlib project publishes source code but no official Windows binaries. hashcat can use a `zlib1.dll` already installed by other software. It requires only zlib 1.2.3.3 or newer.

This document does not recommend an unofficial source for `zlib1.dll`. hashcat loads the DLL into a process handling your hashes, and a copy beside the executable takes precedence over system copies. Its provenance therefore matters. If no trusted `zlib1.dll` is available, recompress the input as `.xz` or `.zst`, for which the upstream projects publish signed Windows builds.

## Licensing of the shipped copies

The three libraries included in the Windows package are redistributed under their respective licenses. The package contains each complete license text in `docs/license_libs/`.

- `liblzma.dll` is liblzma from XZ Utils, under the BSD Zero Clause License. Only liblzma is built, so the XZ Utils command line tools and scripts, some of which carry other licenses, are not part of the package.
- `zlib1.dll` is zlib, under the zlib license.
- `libzstd.dll` is Zstandard, under its BSD license. Zstandard is offered under that license or the GPLv2, and the package takes the BSD one.

Each is built from a pinned upstream release in the release build image rather than committed as a binary, so the version that went into a package is recorded in the file that built it.
