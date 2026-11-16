
This page contains information about packages for hashcat, with guidance [for users](#for-users) and [for package maintainers](#for-package-maintainers).

## For users ##

Many operating system repositories provide a package named `hashcat`. Packaged versions can lag behind the current release, so compare the output of `hashcat -V` with the latest release before reporting a problem. An issue in an older version may already be fixed.

## For package maintainers ##

### Runtime requirements ###

[hashcat-requirements.md](hashcat-requirements.md) lists the minimum version of every runtime hashcat checks, what it does with a device below one, and which libraries are optional. Two details resolve most packaging questions. The CUDA and HIP compiler libraries are packaged separately from their drivers and are dependencies of those backends, not of hashcat. Hardware monitoring is optional on every platform.

### The shared core ###

Setting `SHARED=1` is the default on Linux and macOS. The frontend and every module, bridge and feed link against a single core library, which the package must install alongside the frontend: `libhashcat.so.8` on Linux and `libhashcat.8.dylib` on macOS. A plugin looks for the library one directory above its own location. Building with `SHARED=0` produces self-contained plugins at the cost of a much larger installation.

A development package should include the public plugin headers and the unversioned `libhashcat.so` symlink resolved by `-lhashcat`. Every third-party plugin must be rebuilt for plugin interface 800.

### Compression libraries ###

hashcat no longer bundles zlib or the LZMA SDK. It loads the system zlib, liblzma and libzstd by name at run time, and starts without them, reporting a missing library only when something needs one. This makes them optional runtime dependencies rather than link-time dependencies, although two features require them in practice: the compressed `hashcat.hcstat2` table needs liblzma, so every mask attack and `--benchmark` does, and mode 11600 needs liblzma or zlib depending on the archive. See [hashcat-compression-libraries.md](hashcat-compression-libraries.md).

### What `make install` places where ###

`make install` installs the feeds, the rule files, the PCFG rulesets and the `Python` directory into the shared data directory, where hashcat can resolve them by name. A package that ships only the binary and the core library leaves `-a 4` without its rulesets and mode 73000 without the worker it starts.

Installed builds no longer write to `$HOME/.hashcat`. Potfiles and sessions go to the XDG profile directory and everything hashcat can rebuild goes to the XDG cache directory. No data is migrated, and hashcat reports the old directory alongside both new ones.

### Installing on Windows ###

The Windows release is a portable archive that runs from wherever it is unpacked, and an unpacked copy keeps its potfile, sessions and kernel cache beside `hashcat.exe`. A copy under Program Files, the per user Programs folder (`%LOCALAPPDATA%\Programs`) or winget's packages folder (`%LOCALAPPDATA%\Microsoft\WinGet\Packages`) counts as installed. It keeps that data in `%LOCALAPPDATA%\hashcat` instead, with the sessions and the cache below it, because an upgrade or an uninstall would remove it together with the program folder. A potfile found beside `hashcat.exe` of an installed copy is reported and left where it is.

### Packaging guidance ###

Distribution builds can disable host-specific CPU optimization flags by compiling with `make MAINTAINER_MODE=1` instead of plain `make`.

Setting `MCPU=` selects an explicit target core when the default is unsuitable, and a Raspberry Pi target can be detected from `/proc/cpuinfo`. Make refuses an invocation that mixes native and cross-compilation targets.

### Reproducible builds ###

Two builds of the same commit produce identical bytes when `SOURCE_DATE_EPOCH` and `PRODUCTION=1` are set, which fix the inputs that otherwise vary. The binaries record the hardening flags they were built with rather than inheriting whatever the build machine had.
