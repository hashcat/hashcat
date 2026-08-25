## *hashcat* ##

**hashcat** is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, Windows, and macOS, and has facilities to help enable distributed password cracking.

### License ###

**hashcat** is licensed under the MIT license. Refer to [docs/license.txt](docs/license.txt) for more information.

### Installation ###

Download the [latest release](https://hashcat.net/hashcat/) and unpack it in the desired location. Please remember to use `7z x` when unpacking the archive from the command line to ensure full file paths remain intact.

Your platform may also provide [packages](docs/packages.md).

### Usage/Help ###

Please refer to the [Hashcat Wiki](https://hashcat.net/wiki/) and the output of `--help` for usage information and general help. A list of frequently asked questions may also be found [here](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions). The [Hashcat Forum](https://hashcat.net/forum/) also contains a plethora of information. If you still think you need help by a real human come to [Discord](https://discord.gg/HFS523HGBT).

### Building ###

Refer to [BUILD.md](BUILD.md) for instructions on how to build **hashcat** from source.

Tests:

Travis | Coverity | GitHub Actions
------ | -------- | --------------
[![Hashcat Travis Build status](https://travis-ci.org/hashcat/hashcat.svg?branch=master)](https://travis-ci.org/hashcat/hashcat) | [![Coverity Scan Build Status](https://scan.coverity.com/projects/11753/badge.svg)](https://scan.coverity.com/projects/hashcat) | [![Hashcat GitHub Actions Build status](https://github.com/hashcat/hashcat/actions/workflows/build.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/build.yml)

### Contributing ###

Contributions are welcome and encouraged, provided your code is of sufficient quality. See [CONTRIBUTING.md](CONTRIBUTING.md) for the code style requirements, what a pull request has to contain, and how to test a change before you send it.

If you are using an AI coding agent, point it at the same file. Part 2 of it is addressed to agents directly, and `AGENTS.md`, `CLAUDE.md` and `.github/copilot-instructions.md` are symlinks to it so that most agents pick it up on their own.

### Happy Cracking!
