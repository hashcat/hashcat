# Building and running container with Docker


## Prequesists ##

If you want to run hashcat with your gpus inside docker you first need to install the appropriate container runtime to allow for gpu-passthrough and install usually the latest driver on the host.

### NVidia ###

To enable your docker deamon to support gpu passthrough go here https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html

(The runtime stage in the dockerfile will use an offical nvidia image, make sure your host has at least the same cuda version or a newer version installed. If you wanna change the runtime version of cuda just have a search here https://hub.docker.com/r/nvidia/cuda/tags and exchange it in the dockfile)

Also make sure to install the latest cuda on your host system.

### AMD ###

For AMD go here https://rocm.docs.amd.com/projects/install-on-linux/en/latest/how-to/docker.html


### Intel ###

TBD


## Building and Runtime ##

There will be different dockerfiles for different platforms in the syntax "docker/runtime.PLATFORM.OS.TYPE", each of which only works on that specific platform and requires the host to have the prequesists installed.

Currently there are dockerfiles for cuda (docker/runtime.cuda.OS.TYPE) and amd (docker/runtime.amd.OS.TYPE), more will follow.

Two OS options are available. Use ubuntu26 unless you have a reason not to:

| OS       | cuda base image                      | amd base image                    |
| -------- | ------------------------------------ | --------------------------------- |
| ubuntu26 | nvidia/cuda:13.3.1-devel-ubuntu26.04 | rocm/dev-ubuntu-26.04:7.14.0-full |
| ubuntu24 | nvidia/cuda:12.9.1-devel-ubuntu24.04 | rocm/rocm-terminal                |

The amd ubuntu26 image runs as root, the older amd ubuntu24 image runs as the rocm-user account that its base image provides. That is why the shell prompts differ in the examples below.

Note that rocm/rocm-terminal is unversioned and has not been rebuilt since ROCm 6.4, and it is an ubuntu 22.04 image despite the ubuntu24 name of the dockerfile that uses it. The amd ubuntu26 dockerfile pins a ROCm release instead.

One caveat for nvidia. The only cuda images published for ubuntu 26.04 are cuda 13.x, and cuda 13 dropped code generation for Maxwell, Pascal and Volta. `nvcc --list-gpu-arch` in that image starts at compute_75. If your card is older than Turing, stay on the ubuntu24 dockerfile, which pins cuda 12.9.

Also there are two TYPE options available to build the image:

## 1. With the official binaries (TYPE=release) (docker/runtime.PLATFORM.OS.release)

This will download the version specified in the dockerfile from the official website and use it.

Here is an example for nvidia on ubuntu:

```bash
docker build -f docker/runtime.cuda.ubuntu26.release -t hashcat .
docker run --rm --gpus=all -it hashcat bash
root@docker:~/hashcat# ./hashcat.bin --help
```

Here is an example for amd on ubuntu:

```bash
docker build -f docker/runtime.amd.ubuntu26.release -t hashcat .
docker run --rm --device /dev/kfd --device /dev/dri -it hashcat bash
root@ae67788b1d87:~/hashcat# ./hashcat.bin --help
```

The whole of `/dev/dri` is passed rather than the individual render nodes, so the command does not
depend on how many GPUs the machine has. Naming `renderD128` and `renderD129` explicitly fails on a
single GPU box, where only `renderD128` exists, and docker refuses to start the container at all.

The container above runs as root, which is why no group membership is needed. Adding `--group-add`
to it changes nothing, and `--user` does not turn it into a non-root container either: the ubuntu26
amd image creates no account of its own and keeps hashcat in `/root/hashcat`, and `/root` is mode 700
in the base image, so anyone but root gets `Permission denied` on `hashcat.bin`. Run this image as
root.

Where the render group does matter is the ubuntu24 amd dockerfile, which builds on
`rocm/rocm-terminal`, hands the directory to the `rocm-user` account that base image provides and
ends on `USER rocm-user`. A container from that image is not root, so it needs the group, and it
needs it by numeric id from the host, because the image has no render group of its own:

```bash
docker build -f docker/runtime.amd.ubuntu24.release -t hashcat .
docker run --rm --device /dev/kfd --device /dev/dri --group-add "$(getent group render | cut -d: -f3)" -it hashcat bash
```

## 2. Build the binaries yourself (TYPE=beta) (docker/runtime.PLATFORM.OS.beta)

This will require the official build container to already be built (with the tag hashcat-binaries) successfully and will pull hashcat from it.

What it pulls is the package that `tools/package_bin.sh` writes, not the tree it was built in, so the
layout a beta image runs is the layout that ships: the frontend beside the core, every plugin one
directory below it, and no sources or git checkout carried along. The build image gives that package
a fixed name at `/root/package` for the runtime images to copy, because the name `package_bin.sh`
writes carries the version and sits beside its own `.7z`, which a `COPY --from` cannot tell apart.

Here is an example for nvidia on ubuntu:

```bash
docker build -f docker/BinaryPackage.ubuntu20 -t hashcat-binaries .
docker build -f docker/runtime.cuda.ubuntu26.beta -t hashcat .
docker run --rm --gpus=all -it hashcat bash
root@docker:~/hashcat# ./hashcat.bin --help
```

Here is an example for amd on ubuntu:

```bash
docker build -f docker/BinaryPackage.ubuntu20 -t hashcat-binaries .
docker build -f docker/runtime.amd.ubuntu26.beta -t hashcat .
docker run --rm --device /dev/kfd --device /dev/dri -it hashcat bash
root@ae67788b1d87:~/hashcat# ./hashcat.bin --help
```

