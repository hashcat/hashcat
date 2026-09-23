# Compression libraries

hashcat reads compressed wordlists, hash lists and rule files. It does not carry the code for that, and it does not link it either: the library is loaded when a compressed file is first opened, so hashcat starts and runs normally on a machine that has none of them.

| you open | hashcat loads, in this order | project |
| --- | --- | --- |
| `.gz` | `libz.so.1`, `libz.so` / `zlib1.dll`, `libz.dll`, `zlib.dll` | zlib |
| `.xz`, `.lzma` | `liblzma.so.5`, `liblzma.so` / `liblzma.dll`, `liblzma-5.dll` | XZ Utils |
| `.zst` | `libzstd.so.1`, `libzstd.so` / `libzstd.dll`, `zstd.dll` | Zstandard |

On macOS the names are `libz.1.dylib`, `liblzma.5.dylib` and `libzstd.1.dylib`.

Opening a `.zst` on a machine with no libzstd fails with a message naming every file name it tried and what to install. Another format is unaffected: a `.gz` still opens on a machine that has zlib and no libzstd.

## Two things need a library without you opening a compressed file

Reading a compressed file is not the only thing that reaches for one, so a machine with none of these libraries is not simply a machine that cannot open `.gz`, `.xz` and `.zst`.

The Markov statistics hashcat ships, `hashcat.hcstat2`, are LZMA2 compressed. They are 128 MiB expanded and 235 KiB on disk, and there is no uncompressed version, so every attack that walks a mask loads liblzma before it starts. That is `-a 1`, `-a 3`, `-a 6`, `-a 7` and `-a 12`, and `--benchmark` as well, because it runs `-a 3`. Without liblzma those fail at startup naming the file and the library. `-a 0`, `-a 4`, `-a 5`, `-a 8` and `-a 9` never load the table and are unaffected.

7-Zip hashes, `-m 11600`, carry the compressed data inside the hash line and hashcat decompresses it to verify a candidate. Which library that needs depends on how the archive was written: liblzma for an LZMA1 or LZMA2 archive, zlib for a DEFLATE one.

Both of these were compiled into hashcat before this release, so a machine that ran them before may need a package installed now.

## Seeking inside a compressed wordlist

hashcat does not read a wordlist from one end to the other. Every device works its own stretch of the keyspace at once, and a session that is resumed or started with `--skip` begins in the middle, so hashcat asks the wordlist for a line by its number and expects to be put there.

A plain wordlist answers that by jumping to a byte. A compressed one has no byte to jump to. What is at a given place in the file depends on everything in front of it, so the only way to reach line ten million is to decode the nine million nine hundred thousand before it and throw them away. Every device pays that separately, and a run over 8 GPUs decodes the file 8 times before the first candidate is tried.

The way out is a wordlist compressed in independent pieces. A `.zst` file is a run of frames and an `.xz` file is a run of blocks, and either one decodes without the pieces in front of it, so hashcat can start reading at the piece that holds the line it wants and walk forward from there. It records where those pieces are the first time it reads the file, in the same seek database it already builds for the line count, and every run after that uses it.

### xz

`xz` writes the whole file as one block on its own, and writes one block per chunk as soon as it is asked to use more than one core:

    xz -T0 wordlist

That is the same switch most people already use for the speed, so an `.xz` written the ordinary way on a machine with several cores is usually seekable already. `--block-size` sets the granularity directly, and a smaller block means less to walk through after a seek:

    xz -T0 --block-size=8MiB wordlist

An `.xz` carries an index of its blocks at the end of the file, so hashcat reads where they are rather than working it out. Concatenated `.xz` files are handled too: the index covers every block in the file, whichever stream it belongs to.

### zstd

`zstd` writes one frame for the whole file, even with `-T0`. `pzstd`, which ships with Zstandard, writes one frame per chunk:

    pzstd -p 8 wordlist

The chunk size follows the compression level rather than the thread count, so a wordlist of any size comes out with frames every few megabytes and `-p` only decides how fast it is written. Concatenating `.zst` files with `cat` works as well.

### gzip

A `.gz` has no independent pieces, so it is read from the start as it always was. A wordlist in that format is worth rewriting as `.xz` or `.zst` if the run seeks at all.

### What hashcat says

hashcat reports it once, while building the index, when it meets a large compressed wordlist with nothing in it to seek to, and it names the tool that would change that.

Nothing about any of these files is specific to hashcat. `unxz` and `zstd -d` decompress them, and so does anything else that reads the format.

## Linux and the BSDs

These are almost always installed already, because other programs on the system use them. If one is missing, it is the runtime package you want and not the development package:

    Debian, Ubuntu    zlib1g        liblzma5      libzstd1
    Fedora, RHEL      zlib          xz-libs       libzstd
    Arch              zlib          xz            zstd

## macOS

    brew install zlib xz zstd

## Windows

Windows itself ships none of these. **The official hashcat package ships all three**, in the same folder as `hashcat.exe`, so there is nothing to download and nothing to install or register. They are built from pinned upstream sources in the release build image, and the version that went into a package is recorded in the file that built it.

Replacing one of them with a newer build is supported, and is the way to pick up a security fix without waiting for a hashcat release. Keep the file name the same and leave it next to `hashcat.exe`.

The rest of this section is for a hashcat you built yourself on Windows, which ships with none of them. The folder holding `hashcat.exe` is searched first, and hashcat removes the current working directory from the DLL search path. `PATH` remains in the standard Windows search order, but placing the DLL next to `hashcat.exe` is the predictable choice. Two of the three projects publish a Windows build themselves:

**xz**, for `.xz` files. From https://github.com/tukaani-project/xz/releases take the `xz-<version>-windows.zip` and copy `bin_x86-64\liblzma.dll` next to `hashcat.exe`. The release is signed, and the `.sig` file beside it can be checked if you want to.

**Zstandard**, for `.zst` files. From https://github.com/facebook/zstd/releases take the `zstd-v<version>-win64.zip` and copy `dll\libzstd.dll` next to `hashcat.exe`.

Neither file needs installing or registering. Copy it into the hashcat folder and it is found.

**`.gz` is the awkward one for a build of your own.** The zlib project ships source only and has never published a Windows build, so there is no official file to point at. hashcat will use a `zlib1.dll` if one is already on the machine, and many are, put there by other software. It asks for nothing newer than zlib 1.2.3.3, which is from 2010, so an old copy is fine.

What this page will not do is name a third party to download `zlib1.dll` from. hashcat is loading that file into a process handling your hashes, and a DLL beside the executable takes precedence over every system one, so where it came from matters more here than convenience does. If you have no `zlib1.dll` you trust, recompress the file as `.xz` or `.zst`, both of which have a signed build from the project that wrote them.

## Licensing of the shipped copies

The three the Windows package carries are redistributed under their own terms, and the full text of each is in `docs/license_libs/` in the same package.

- `liblzma.dll` is liblzma from XZ Utils, under the BSD Zero Clause License. Only liblzma is built, so the XZ Utils command line tools and scripts, some of which carry other licenses, are not part of the package.
- `zlib1.dll` is zlib, under the zlib license.
- `libzstd.dll` is Zstandard, under its BSD license. Zstandard is offered under that license or the GPLv2, and the package takes the BSD one.

Each is built from a pinned upstream release in the release build image rather than committed as a binary, so the version that went into a package is recorded in the file that built it.
