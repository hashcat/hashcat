# Compiling hashcat binaries with Docker

To build both Linux and Windows binaries in a clean and reproducible environment a dockerfile is available.
It is not considered to be used as a runtime OS.

Using the **HashcatBinaries** docker with the default settings will create a single version of hashcat, compiled with clang.

### Building ###

By default, this Docker sets MAINTAINER_MODE to 1. In the following example, we force this setting to 0 using an additional argument.

```bash
docker build --build-arg UBUNTU_VERSION=16.04 --build-arg MAINTAINER_MODE=0 -f docker/hashcat_binaries.ubuntu -t hashcat_binaries:16.04 .
```

This will create a Docker image based on Ubuntu 16.04 using hashcat-toolchain (https://hub.docker.com/r/gm4tr1x/hashcat-toolchain).
By adding `--build-arg CACHE_BUST=$(date +%s)`, the hashcat sources will be forced to re-download and rebuild.

If you want to compile hashcat with gcc/mingw only, you can override the default settings using `--build-arg USE_GCC=1 --build-arg USE_CLANG=0`.
Likewise, you can get two versions of hashcat (compiled with both gcc/mingw and clang) by using `--build-arg USE_GCC=1`.

Moreover, by adding `--build-arg WITH_CODE_ANALYSIS=1` clang-tools (specifically clang-tidy and scan-build) will be used to perform a static code analysis on the hashcat sources.
The results will be saved in: `/root/code-analysis`.

Optionally you can place additional *.patch or *.diff files into `patches/` folder (`patches/hashcat_binaries/` in this case). They will be applied before compiling.

They are applied with `git apply`, so they have to be in git's own diff format, which is what `git diff` and `git format-patch` write. A patch that fails to apply stops the build.

**If your patch touches a binary file, produce it with `git diff --binary`.** A plain `git diff` writes only `Binary files a/x and b/x differ` for such a file. That line names the change without carrying it, so nothing can apply it, and `git apply` will refuse the whole patch rather than apply the text half and drop the rest.

### Which sources get built ###

`HASHCAT_REF` decides which tree is packaged. It is a git ref in the hashcat repository, and it defaults to the release this file shipped with, so a build with no further arguments produces that release rather than current master.
Your working tree is not built at all. It provides this dockerfile and the `patches/` folder, and the sources are cloned from GitHub.

For a beta carrying the current state of master, name it:

```bash
docker build --build-arg UBUNTU_VERSION=16.04 --build-arg MAINTAINER_MODE=0 --build-arg HASHCAT_REF=master --build-arg CACHE_BUST=$(date +%s) -f docker/hashcat_binaries.ubuntu -t hashcat_binaries:16.04 .
```

For a beta you hand out, name the commit instead, `--build-arg HASHCAT_REF=1234abc`, so that the same command rebuilds the same package later. Master moves, and a build from it can only be identified after the fact, from the name of the package it produced.

A ref older than v8.0.0 is refused rather than built. This file passes `CC_WIN=clang`, and a Makefile from before the shared core has no way to tell clang which target a Windows artifact is for.

`SOURCE_DATE_EPOCH` pins the build time that goes into the binaries, which is otherwise the moment of the build. Rebuilding a release to the same bytes therefore means passing the commit time of its tag, `--build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct v8.0.0)`. A beta has no use for it.

### Output ###

Using the default settings, the resulting output package will be located in: `/root/xy/hashcat-<version>.7z`,
or `hashcat-<version>-<compiler>.7z` if both `USE_GCC` and `USE_CLANG` are set to 1.

`<version>` is the version the built binary reports, which the package script asks the Makefile for rather than writing out itself.
A tag gives the release version on its own, `hashcat-8.0.0.7z`. Any other commit gives git's description of it, `hashcat-8.0.0-9-g1234abc.7z`, so a beta package is distinguishable from the release and from another beta.

You can copy it to your host with this command:

```bash
docker run --rm \
  -e HOST_UID=$(id -u) \
  -e HOST_GID=$(id -g) \
  -v $(pwd):/out \
  hashcat_binaries:16.04 \
  bash -c "cp /root/xy/hashcat-*.7z /out && chown \$HOST_UID:\$HOST_GID /out/hashcat-*.7z"
```

The package will be available on your host machine in the `out` directory.

### Debug ###

In case you want to play around in the docker, run:

```bash
docker run --rm -it hashcat_binaries:16.04 /bin/bash
```
