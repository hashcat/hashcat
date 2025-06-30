# Compiling hashcat binaries with Docker

To build both Linux and Windows binaries in a clean and reproducible environment a dockerfile is available.
It is not considered to be used as a runtime OS.

### Building ###

```bash
docker build -f docker/BinaryPackage.ubuntu20 -t hashcat-binaries .
```

This will create a Docker image with all required toolchains and dependencies.

Optionally you can place custom *.patch or *.diff files into `patches/` folder. They will be applied before compiling.

### Output ###

The resulting output package will be located in: `/root/xy/hashcat-<version>.7z`.

You can copy it to your host with this command:

```bash
docker run --rm \
  -e HOST_UID=$(id -u) \
  -e HOST_GID=$(id -g) \
  -v $(pwd):/out \
  hashcat-binaries \
  bash -c "cp /root/xy/hashcat-*.7z /out && chown \$HOST_UID:\$HOST_GID /out/hashcat-*.7z"
```

The package will be available on your host machine in the `out` directory.

### Debug ###

In case you want to play around in the docker, run:

```bash
docker run --rm -it hashcat-binaries /bin/bash
```

