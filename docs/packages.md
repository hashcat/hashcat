
This page contains information about packages for hashcat, with guidance [for users](#for-users) and [for package maintainers](#for-package-maintainers).

## For users ##

Many OS packaging systems have a package simply called 'hashcat'. A packaged version is often behind the current release, so check what `hashcat -V` prints against the latest release before reporting a problem. Most reports about an older version describe something already fixed.

## For package maintainers ##

### Runtime requirements ###

[hashcat-requirements.md](hashcat-requirements.md) lists the minimum version of every runtime hashcat checks, what it does with a device below one, and which libraries are optional. Two points decide most packaging questions: the CUDA and HIP compiler libraries live in a different package from the driver and are dependencies of those backends rather than of hashcat, and hardware monitoring is optional everywhere.

### The shared core ###

`SHARED=1` is the default on Linux and macOS. The frontend and every module, bridge and feed link against one core library, which the package has to ship beside the frontend: `libhashcat.so.7` on Linux, `libhashcat.7.dylib` on macOS. A plugin looks for it one directory above its own. Building with `SHARED=0` restores self-contained plugins, at the cost of a much larger install.

A development package wants the public plugin headers and the unversioned `libhashcat.so` symlink, which is what `-lhashcat` resolves against. Every third-party plugin has to be rebuilt for plugin interface 720.

### Compression libraries ###

hashcat no longer bundles zlib or the LZMA SDK. It loads the system zlib, liblzma and libzstd by name at run time, and starts without them, reporting a missing library only when something needs one. That makes them optional dependencies rather than link-time ones, but two cases are not optional in practice: the compressed `hashcat.hcstat2` table needs liblzma, so every mask attack and `--benchmark` does, and mode 11600 needs liblzma or zlib depending on the archive. See [hashcat-compression-libraries.md](hashcat-compression-libraries.md).

### What `make install` places where ###

`make install` installs the feeds, the rule files and the PCFG rulesets into the shared data directory, where hashcat resolves them by name. A package that ships only the binary and the core library leaves `-a 4` without its rulesets.

Installed builds no longer write to `$HOME/.hashcat`. Potfiles and sessions go to the XDG profile directory and everything hashcat can rebuild goes to the XDG cache directory. Nothing is migrated, and hashcat reports the old directory alongside both new ones.

### Packaging guidance ###

Distribution builds can disable host-specific CPU optimization flags by compiling with `make MAINTAINER_MODE=1` instead of plain `make`.

`MCPU=` names an explicit target core when the default is not what the package wants, and a Raspberry Pi target can be read from `/proc/cpuinfo`. Make refuses an invocation that mixes native and cross-compilation targets.

### Reproducible builds ###

Two builds of the same commit produce identical bytes when `SOURCE_DATE_EPOCH` and `PRODUCTION=1` are set, which fix the inputs that otherwise vary. The binaries record the hardening flags they were built with rather than inheriting whatever the build machine had.
