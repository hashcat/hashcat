## *hashcat* ##

hashcat is a highly optimized password recovery platform for GPUs, CPUs, and large distributed systems.

### Features ###

* World's fastest password cracker
* World's first and only in-kernel rule engine, usable in every attack mode
* Free and open source, under the MIT license
* Multi-OS: Linux, Windows and macOS, and builds from source on BSD and Android
* Multi-backend: CUDA, HIP, Metal and OpenCL
* Multi-device: several devices, and mixed device types, in one system
* Multi-hash: cracks large numbers of hashes at once
* Over 630 hash modes, each written with performance in mind
* Hash recipes: write a hash as an expression, such as `pbkdf2_sha256(md5(pass), salt, iter, 32)`, fully GPU accelerated
* 10 attack modes for password candidate generation
* Assimilation bridge: add a hash mode in C, Python or Rust, without writing a kernel
* Brain: skips candidates an earlier session already tried
* Distributed cracking networks, using an overlay
* Reads candidates from a wordlist, from stdin, or from another program
* Reads wordlists compressed with gzip, xz or zstd
* Seekable wordlists
* Markov chain keyspace ordering, so the likely candidates come first
* Automatic performance tuning per device
* Interactive pause, resume, rewind and advance
* Named sessions, and restore after an interruption
* Built-in benchmark
* Integrated thermal watchdog

### License ###

**hashcat** is licensed under the MIT license. See [docs/license.txt](docs/license.txt).

### Installation ###

Download the [latest release](https://hashcat.net/hashcat/) and unpack it where you want it. Use `7z x` when unpacking from the command line, so the full file paths stay intact.

Your platform may also provide [packages](docs/packages.md). The drivers and runtimes hashcat needs are listed in [docs/hashcat-requirements.md](docs/hashcat-requirements.md).

### Building ###

Building from source is optional. The release package is the same program, and a binary you build yourself will not crack any faster. Build it if you want a change of your own, a fix that is in master but not yet released, or a platform we do not ship a binary for.

See [BUILD.md](BUILD.md) for how.

Tests:

Build | BSD | Rust | Test | Fuzz
----- | --- | ---- | ---- | ----
[![Build](https://github.com/hashcat/hashcat/actions/workflows/build.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/build.yml) | [![BSD](https://github.com/hashcat/hashcat/actions/workflows/bsd.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/bsd.yml) | [![Rust tests](https://github.com/hashcat/hashcat/actions/workflows/rust.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/rust.yml) | [![test](https://github.com/hashcat/hashcat/actions/workflows/test.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/test.yml) | [![fuzz](https://github.com/hashcat/hashcat/actions/workflows/fuzz.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/fuzz.yml)

### Usage and help ###

Start with `--help`, also kept in the tree as [docs/hashcat-help.md](docs/hashcat-help.md). One example hash per mode is in [docs/hashcat-example-hashes.md](docs/hashcat-example-hashes.md).

The [wiki](https://hashcat.net/wiki/) and the [FAQ](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions) go further. The [forum](https://hashcat.net/forum/) holds years of answered questions. If you still need help from a real human, come to [Discord](https://discord.gg/HFS523HGBT).

### Documentation ###

The [docs](docs/) directory covers each feature. The ones people ask about most:

* [Hash recipes](docs/hashcat-hash-recipe.md), for cracking a custom hash scheme without writing a hash mode
* [Plugin development guide](docs/hashcat-plugin-development-guide.md), for adding a hash mode
* [Assimilation bridge](docs/hashcat-assimilation-bridge.md), and its [Python](docs/hashcat-python-plugin-quickstart.md) and [Rust](docs/hashcat-rust-plugin-quickstart.md) quickstarts
* [FPGA setup](docs/hashcat-fpga-setup.md), for running bcrypt on FPGA boards with mode 75000
* [Generic attack mode](docs/hashcat-generic-attack-mode.md), [PCFG](docs/hashcat-pcfg.md), [table](docs/hashcat-table.md) and [association](docs/hashcat-association.md) attacks
* [Brain](docs/hashcat-brain.md), for skipping candidates an earlier session already tried
* [Release notes for v8.0.0](docs/releases_notes_v8.0.0.md), and the full [changelog](docs/changes.txt)

### Contributing ###

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the code style, what a pull request needs, and how to test a change before you send it.

### Security ###

[SECURITY.md](SECURITY.md) has how to report a vulnerability, and what counts as one.

### Happy Cracking!
