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

### Output ###

Using the default settings, the resulting output package will be located in: `/root/xy/hashcat-<version>.7z`,
or `hashcat-<version>-<compiler>.7z` if both `USE_GCC` and `USE_CLANG` are set to 1.

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
