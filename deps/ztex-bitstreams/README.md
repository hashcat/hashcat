# ZTEX USB-FPGA 1.15y device binaries

This directory documents binary dependencies that are **not** stored in the repository or downloaded by the build.

Mode 75000 (bcrypt) supports the ZTEX USB-FPGA Module 1.15y, which contains four Spartan-6 FPGAs. The board loses its configuration at power-off, so hashcat uploads the required firmware and bitstream at the first start after a power cycle.

| File | What it is | Size |
| --- | --- | --- |
| `inouttraffic.ihx` | firmware for the board's Cypress FX2 microcontroller | 17 KB |
| `ztex115y_bcrypt.bit` | the bcrypt design for one Spartan-6 | 3.9 MB |

The firmware is shared by all designs. The bitstream is algorithm-specific.

`run/ztex/` upstream also carries `ztex115y_descrypt.bit`, `ztex115y_md5crypt.bit`, `ztex115y_sha256crypt.bit` and `ztex115y_sha512crypt.bit`, each about 3.9 MB. **hashcat redistributes only the bcrypt one**, because bcrypt is the only algorithm it has an FPGA mode for. Those four are listed here to clarify the scope. Adding one of them is part of adding the matching hash mode rather than a documentation change.

## Origin

Both files are unmodified prebuilt images from `run/ztex/` in the John the Ripper source tree. Denis Burykin is their author. The firmware is built on intraffic, an example from the ZTEX SDK, and also carries ZTEX GmbH's copyright.

They are redistributed because the current build environment cannot reproduce them. Vivado 2026.1 does not support the Spartan-6, and the last supporting toolchain, ISE, is obsolete. The design sources and the ISE project are public in John the Ripper's `src/ztex/fpga-bcrypt/`, but a rebuild needs an archived ISE installation and upstream's partitioned place and route flow, and would not reproduce these exact images.

These files therefore remain synchronized with the unmodified binaries published by John the Ripper and should be updated only when upstream changes them.

## Why the binaries are not vendored

hashcat vendors third-party **source** under `deps/`. These files are approximately 3.9 MB of non-reproducible binaries that would otherwise be included in every clone.

Cloning the complete John the Ripper repository is also unnecessary because hashcat requires only these two files from a source tree larger than 100 MB.

The files are published alongside hashcat's bitstreams:

    https://hashcat.net/bitstreams/ztex/

When it detects a board without these files installed, hashcat prints the commands required to download them. It does not download files automatically.

## Installation paths

    <profile_dir>/fpga/    the user's own copy, no root needed
    <shared_dir>/fpga/     the install's copy, one file serving every account

hashcat searches the profile directory first. In a local build, both paths resolve to the directory containing the `hashcat` binary.

## Licence

`docs/license_libs/ZTEX_BITSTREAM_LICENSE.txt`.

The two files are not under the same terms and the difference matters.

The `.bit` design is Denis Burykin's. Most of its source files permit redistribution with no further conditions, but a few carry no terms, and John the Ripper places those under the GPL, version 2 or later. The bitstream is therefore distributed under the GPL as well, and its source is published beside it as `ztex115y_bcrypt-source.tar.xz`, an archive of John the Ripper's `src/ztex/fpga-bcrypt/` at the commit that built it.

`inouttraffic.ihx` is **GPLv3**. It is built from a ZTEX GmbH SDK example, and the GPL followed the derivative. Distributing that binary means distributing its source with it.

John the Ripper tracks the binary at `run/ztex/inouttraffic.ihx` and its source at `src/ztex/ez-usb/inouttraffic.c` in the same repository. hashcat publishes the source, build README and GPLv3 text beside the `.ihx`. Together, these accompanying files occupy 45 KB.

Neither file is linked into hashcat or built into it. hashcat opens them at runtime and writes their bytes to a USB device, exactly as a programmer would, so hashcat's own licence is unaffected.
