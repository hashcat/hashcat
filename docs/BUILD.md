oclHashcat build documentation
=
# Revision:
* 1.2

# Authors:
* Gabriele Gristina <<matrix@hashcat.net>>
* Christoph Heuwieser <<dropdead@hashcat.net>>

# Building oclHashcat for Linux and OSX

First get a copy of the **oclHashcat** repository

```sh
$ git clone https://github.com/hashcat/oclHashcat.git
```

Run "make"

```sh
$ make
```

to install it run "make install"

```sh
$ make install
```

# Building oclHashcat for Windows

The following third party library is required:

- NVAPI R352 ( https://developer.nvidia.com/nvapi )

Download the third party library listed above and put the .zip file into the *deps/tmp* directory.

- R352-developer.zip 

Install the dependencies (root permission needed for apt-get install command)

```sh
$ ./tools/deps.sh
```

- build all binaries:

```sh
$ make win32 win64
```

# To build all binaries ("make binaries") you need to first clone the OpenCL-Headers within the main folder:

```sh
$ git clone https://github.com/KhronosGroup/OpenCL-Headers deps/OpenCL-Headers/CL
```

the tools/deps.sh script does not clone this repo automatically since for native compilation it is not needed.

=
Enjoy your fresh **oclHashcat** binaries ;)
