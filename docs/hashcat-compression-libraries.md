# Compression libraries

hashcat reads compressed wordlists, hash lists and rule files. It does not carry the code for
that, and it does not link it either: the library is loaded when a compressed file is first
opened, so hashcat starts and runs normally on a machine that has none of them.

| you open | hashcat loads, in this order | project |
| --- | --- | --- |
| `.gz` | `libz.so.1`, `libz.so` / `zlib1.dll`, `libz.dll`, `zlib.dll` | zlib |
| `.xz`, `.lzma` | `liblzma.so.5`, `liblzma.so` / `liblzma.dll`, `liblzma-5.dll` | XZ Utils |
| `.zst` | `libzstd.so.1`, `libzstd.so` / `libzstd.dll`, `zstd.dll` | Zstandard |

On macOS the names are `libz.1.dylib`, `liblzma.5.dylib` and `libzstd.1.dylib`.

Only the format you actually use needs its library. Opening a `.zst` on a machine with no
libzstd fails with a message naming every file name it tried and what to install. Nothing else
about that run is affected.

## Linux and the BSDs

These are almost always installed already, because other programs on the system use them. If one
is missing, it is the runtime package you want and not the development package:

    Debian, Ubuntu    zlib1g        liblzma5      libzstd1
    Fedora, RHEL      zlib          xz-libs       libzstd
    Arch              zlib          xz            zstd

## macOS

    brew install zlib xz zstd

## Windows

Windows itself ships none of these. **The official hashcat package ships all three**, in the same
folder as `hashcat.exe`, so there is nothing to download and nothing to install or register. They
are built from pinned upstream sources in the release build image, and the version that went into a
package is recorded in the file that built it.

Replacing one of them with a newer build is supported, and is the way to pick up a security fix
without waiting for a hashcat release. Keep the file name the same and leave it next to
`hashcat.exe`.

The rest of this section is for a hashcat you built yourself on Windows, which ships with none of
them. A DLL has to sit next to `hashcat.exe`: the folder holding the executable is searched, and the
current directory and `PATH` are not searched at all. Two of the three projects publish a Windows
build themselves:

**xz**, for `.xz` files. From https://github.com/tukaani-project/xz/releases take the
`xz-<version>-windows.zip` and copy `bin_x86-64\liblzma.dll` next to `hashcat.exe`. The release
is signed, and the `.sig` file beside it can be checked if you want to.

**Zstandard**, for `.zst` files. From https://github.com/facebook/zstd/releases take the
`zstd-v<version>-win64.zip` and copy `dll\libzstd.dll` next to `hashcat.exe`.

Neither file needs installing or registering. Copy it into the hashcat folder and it is found.

**`.gz` is the awkward one for a build of your own.** The zlib project ships source only and has
never published a Windows build, so there is no official file to point at. hashcat will use a
`zlib1.dll` if one is already on the machine, and many are, put there by other software. It asks
for nothing newer than zlib 1.2.3.3, which is from 2010, so an old copy is fine.

What this page will not do is name a third party to download `zlib1.dll` from. hashcat is loading
that file into a process handling your hashes, and a DLL beside the executable takes precedence over
every system one, so where it came from matters more here than convenience does. If you have no
`zlib1.dll` you trust, recompress the file as `.xz` or `.zst`, both of which have a signed build
from the project that wrote them.

## Licensing of the shipped copies

The three the Windows package carries are redistributed under their own terms, and the full text of
each is in `docs/license_libs/` in the same package.

- `liblzma.dll` is liblzma from XZ Utils, under the BSD Zero Clause License. Only liblzma is built,
  so the XZ Utils command line tools and scripts, some of which carry other licenses, are not part
  of the package.
- `zlib1.dll` is zlib, under the zlib license.
- `libzstd.dll` is Zstandard, under its BSD license. Zstandard is offered under that license or the
  GPLv2, and the package takes the BSD one.

Each is built from a pinned upstream release in the release build image rather than committed as a
binary, so the version that went into a package is recorded in the file that built it.
