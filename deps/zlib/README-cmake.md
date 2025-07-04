# For building with cmake at least version 3.12 (minizip 3.12) is needed

In most cases the usual

    cmake -S . -B build -D CMAKE_BUILD_TYPE=Release

will create everything you need, however if you want something off default you can adjust several options fit your needs.
Every option is list below (excluding the cmake-standard options), they can be set via cmake-gui or on cmdline with

    -D<option>=ON/OFF

## ZLIB-options with defaults ##

    ZLIB_BUILD_TESTING=ON -- Enable Zlib Examples as tests

    ZLIB_BUILD_SHARED=ON -- Enable building zlib shared library

    ZLIB_BUILD_STATIC=ON -- Enable building zlib static library

    ZLIB_BUILD_MINIZIP=ON -- Enable building libminizip contrib library

If this option is turned on, additional options are available from minizip (see below)

    ZLIB_INSTALL=ON -- Enable installation of zlib

    ZLIB_PREFIX=OFF -- prefix for all types and library functions, see zconf.h.in

    ZLIB_INSTALL_COMPAT_DLL=ON -- Install a copy as zlib1.dll

This option is only on windows available and may/will be turned off and removed somewhen in the future.
If you rely cmake for finding and using zlib, this can be turned off, as `zlib1.dll` will never be used.

## minizip-options with defaults ##

    MINIZIP_BUILD_SHARED=ON -- Enable building minizip shared library

    MINIZIP_BUILD_STATIC=ON -- Enable building minizip static library

    MINIZIP_BUILD_TESTING=ON -- Enable testing of minizip

    MINIZIP_ENABLE_BZIP2=ON -- Build minizip withj bzip2 support

A usable installation of bzip2 is needed or config will fail. Turn this option of in this case.

    MINIZIP_INSTALL=ON -- Enable installation of minizip

    MINIZIP_INSTALL_COMPAT_DLL=ON -- Install a copy as libminizip-1.dll

This option is only available on mingw as they tend to name this lib different. Maybe this will also be
removed in the future as. If you rely cmake for finding and using zlib, this can be turned off, as
the other file will never be used.

## Using the libs ##

To pull in what you need it's enough to just write

    find_package(ZLIB CONFIG)

or

    find_package(minizip CONFIG)

in your CMakeLists.txt, however it is advised to specify what you really want via:

    find_package(ZLIB CONFIG COMPONENTS shared static REQUIRED)

or

    find_package(minizip CONFIG COMPONENTS shared static REQUIRED)

As it's possible to only build the shared or the static lib, you can make sure that everything you need
is found. If no COMPONENTS are requested, everything that is found will satisfy your request. If the
libraries are optional in you project, you can omit the REQUIRED and check yourself if the targets you
want to link against are created.

When you search for minizip, it will search zlib for you, so only one of both is needed.

## Imported targets ##

When found the following targets are created for you:

    ZLIB::ZLIB and ZLIB::ZLIBSTATIC -- for zlib
    MINIZIP::minizip and MINIZIP::minizipstatic -- for minizip
