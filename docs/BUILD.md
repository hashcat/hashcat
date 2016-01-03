oclHashcat build documentation
=
# Revision:
* 1.1

# Authors:
* Gabriele Gristina <<matrix@hashcat.net>>
* Christoph Heuwieser <<dropdead@hashcat.net>>

# Dependencies

To compile **oclHashcat** the following third party libraries are required:

- ADL_SDK v8.0 ( http://developer.amd.com/tools-and-sdks/graphics-development/display-library-adl-sdk/ )
- NVAPI R352 ( https://developer.nvidia.com/nvapi )
- GDK v352_55 ( https://developer.nvidia.com/gpu-deployment-kit )

The next thing to do is download all the third party libraries listed above and put these files into the *deps/tmp* directory.

The following files are needed inside the *deps/tmp* directory:
    
    ADL_SDK8.zip
    R352-developer.zip
    gdk_linux_amd64_352_55_release.run
    
# Building oclHashcat
First get a copy of the **oclHashcat** repository

```sh
$ git clone https://github.com/hashcat/oclHashcat.git
```
Install the dependencies

```sh
$ cd oclHashcat
$ sudo ./tools/deps.sh
```

Run "make"

```sh
$ make
```

to install it run "make install"

```sh
$ make install
```

Useful tricks:
- build all binaries (see Note1 and Note2):
```sh
$ make binaries
```

Note1: to install all binaries ("make binaries") you need to first clone the OpenCL-Headers within the main folder:

```sh
$ git clone https://github.com/KhronosGroup/OpenCL-Headers deps/OpenCL-Headers/CL
```

the tools/deps.sh script does not clone this repo automatically since for native compilation it is not needed.

Note2: if you get an error like the following one for "make binaries"

```sh
/usr/bin/ld: cannot find -lOpenCL
```

the main reason is probably that the 32-bit version of libOpenCL.so was not found.

A possible solution is to just symbolic link it (if the 32-bit version of libOpenCL.so.1 exists), for example:

```sh
sudo ln -s /usr/lib/i386-linux-gnu/libOpenCL.so.1 /usr/lib/i386-linux-gnu/libOpenCL.so
```

=
Enjoy your fresh **oclHashcat** binaries ;)
