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

### Runtime ###

If you want to run hashcat with your gpus inside docker you first need to install the appropriate container runtime.
For nvidia go here https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html
(The runtime stage in the dockerfile will use an offical nvidia image, make sure your host has at least the same cuda version or a newer version installed.)
For AMD go here https://rocm.docs.amd.com/projects/install-on-linux/en/latest/how-to/docker.html



```bash
docker run --rm --gpus=all -it hashcat-binaries hashcat --help
```
