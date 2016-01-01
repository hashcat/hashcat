oclHashcat build documentation
=
# Revision:
* 1.1

# Authors:
* Gabriele Gristina <<matrix@hashcat.net>>
* Christoph Heuwieser <<dropdead@hashcat.net>>

# Dependencies

To compile **oclHashcat** the following third party libraries are required:

- AMD-APP-SDK v3.0 ( http://developer.amd.com/tools-and-sdks/opencl-zone/amd-accelerated-parallel-processing-app-sdk/ )
- ADL_SDK v8.0 ( http://developer.amd.com/tools-and-sdks/graphics-development/display-library-adl-sdk/ )
- NVAPI R352 ( https://developer.nvidia.com/nvapi )
- GDK v352_55 ( https://developer.nvidia.com/gpu-deployment-kit )

The next thing to do is download all the third party libraries listed above and put these files into the *deps/tmp* directory.

The following files are needed inside the *deps/tmp* directory:
    
    ADL_SDK8.zip
    R352-developer.zip
    gdk_linux_amd64_352_55_release.run
    AMD-APP-SDKInstaller-v3.0.130.135-GA-linux64.tar.bz2
    
# Building oclHashcat
First get a copy of **oclHashcat** repository

```sh
$ git clone https://github.com/hashcat/oclHashcat.git
```
Install the dependencies

```sh
$ cd oclHashcat
$ sudo ./tools/deps.sh
```

Run "make all"

```sh
$ make all
```

Useful tricks:
- build only *Linux* binaries
```sh
$ make linux
```
- build only *Windows* binaries
```sh
$ make windows
```

=
Enjoy your fresh **oclHashcat** binaries ;)
