## *hashcat* ##

hashcat is a highly optimized password recovery platform for GPUs, CPUs, and large distributed systems.

### Features ###

* World's fastest password cracker
* World's first and only in-kernel rule engine
* Free and open source, under the MIT license
* Multi-OS: Linux, Windows and macOS
* Multi-backend: CUDA, HIP, Metal and OpenCL
* Multi-device: several devices, and mixed device types, in one system
* Multi-hash: cracks large numbers of hashes at once
* Over 590 hash modes, each written with performance in mind
* 5 attack modes: wordlist, brute-force, PCFG, hybrid and association
* Assimilation bridge: add a hash mode in C, Python or Rust, without writing a kernel
* Brain: skips candidates an earlier session already tried
* Distributed cracking networks, using an overlay
* Reads candidates from a wordlist, from stdin, or from another program
* Markov chain keyspace ordering, so the likely candidates come first
* Automatic performance tuning per device
* Interactive pause and resume
* Named sessions, and restore after an interruption
* Built-in benchmark
* Integrated thermal watchdog
* Hex salt and hex charset, for hashes and character sets that are not text
* Encrypted plains: crack a hash for someone else without being able to read the password
* Keyboard layout mapping, for full disk encryption passwords typed on a non-US keyboard

### License ###

**hashcat** is licensed under the MIT license. See [docs/license.txt](docs/license.txt).

### Installation ###

Download the [latest release](https://hashcat.net/hashcat/) and unpack it where you want it. Use `7z x` when unpacking from the command line, so the full file paths stay intact.

Your platform may also provide [packages](docs/packages.md).

### Building ###

Building from source is optional. The release package is the same program, and a binary you build yourself will not crack any faster. Build it if you want a change of your own, a fix that is in master but not yet released, or a platform we do not ship a binary for.

See [BUILD.md](BUILD.md) for how.

Tests:

Build | BSD | Rust
----- | --- | ----
[![Build](https://github.com/hashcat/hashcat/actions/workflows/build.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/build.yml) | [![BSD](https://github.com/hashcat/hashcat/actions/workflows/bsd.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/bsd.yml) | [![Rust tests](https://github.com/hashcat/hashcat/actions/workflows/rust.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/rust.yml)

### Usage and help ###

Start with `--help`, also kept in the tree as [docs/hashcat-help.md](docs/hashcat-help.md). One example hash per mode is in [docs/hashcat-example-hashes.md](docs/hashcat-example-hashes.md).

The [wiki](https://hashcat.net/wiki/) and the [FAQ](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions) go further. The [forum](https://hashcat.net/forum/) holds years of answered questions. If you still need help from a real human, come to [Discord](https://discord.gg/HFS523HGBT).

### Documentation ###

The [docs](docs/) directory covers each feature. The ones people ask about most:

* [Plugin development guide](docs/hashcat-plugin-development-guide.md), for adding a hash mode
* [Assimilation bridge](docs/hashcat-assimilation-bridge.md), and its [Python](docs/hashcat-python-plugin-quickstart.md) and [Rust](docs/hashcat-rust-plugin-quickstart.md) quickstarts
* [Generic attack mode](docs/hashcat-generic-attack-mode.md) and [PCFG](docs/hashcat-pcfg.md)
* [Brain](docs/hashcat-brain.md), [slow candidates](docs/slow-candidates-mode.md), [encrypted plains](docs/hashcat-encrypted-plains.md)
* [Keyboard layout mapping](docs/keyboard-layout-mapping.md)
* [Release notes for v7.1.0](docs/releases_notes_v7.1.0.md), and the full [changelog](docs/changes.txt)

### Contributing ###

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the code style, what a pull request needs, and how to test a change before you send it.

### Security ###

[SECURITY.md](SECURITY.md) has how to report a vulnerability, and what counts as one.

### Happy Cracking!
