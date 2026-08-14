##
## Author......: See docs/credits.txt
## License.....: MIT
##

##
## What this file builds, for somebody opening it for the first time
##
## Four kinds of thing come out of a build. The core, which is a shared library and holds everything
## hashcat knows how to do. The frontend, hashcat or hashcat.exe, which is a small program that calls
## the core. The plugins, which are the 593 modules, the bridges and the feeds, each a shared object
## that the core loads at runtime. And the kernels under OpenCL/, which are not compiled here at all,
## because the GPU driver compiles them when hashcat runs.
##
## Everything is built for a platform, which is a compiler plus its flags plus which core to link
## against. NATIVE builds for the machine doing the building. LINUX and WIN cross compile a release.
## An artifact says which platform it belongs to in its own name, so obj/backend.WIN.o and hashcat.bin
## are never in doubt, and the rules that build them never have to guess.
##
## If you are writing a plugin, the section named Plugins below is the part that concerns you, and
## docs/hashcat-plugin-development-guide.md is the longer version. The short story is that a module
## dropped into src/modules/ is picked up on the next make with nothing to register anywhere.
##
## The switches worth knowing are directly below. SHARED=0 goes back to the old arrangement where
## every plugin carries its own copy of the core. DEBUG=1 builds with debug information and does not
## strip it off. PRODUCTION=1 is what a release is built with.
##

DEBUG                   := 0
PRODUCTION              := 0
PRODUCTION_VERSION      := v7.1.2
MACOS_UNIVERSAL_BINARY  ?= 0
ENABLE_LTO              ?= 0
ENABLE_CUBIN            ?= 1
ENABLE_BRAIN            ?= 1
ENABLE_UNRAR            ?= 1
USE_MOLD                ?= 0
USE_SYSTEM_LZMA         ?= 0
USE_SYSTEM_ZLIB         ?= 0
USE_SYSTEM_OPENCL       ?= 0
USE_SYSTEM_XXHASH       ?= 0
## do not change, requires some hacks
USE_SYSTEM_UNRAR        ?= 0
MAINTAINER_MODE         ?= 0

##
## Detect Operating System
##

UNAME                   := $(shell uname -s)

# Detect Android
ANDROID_DETECT := $(findstring Android,$(shell uname -a))
ifneq (,$(ANDROID_DETECT))
  UNAME                   := Android
endif

# we need to strip the windows version number to be able to build hashcat on cygwin hosts
UNAME                   := $(patsubst CYGWIN_NT-%,CYGWIN,$(UNAME))

# same for msys
UNAME                   := $(patsubst MSYS_NT-%,MSYS2,$(UNAME))
UNAME                   := $(patsubst MINGW32_NT-%,MSYS2,$(UNAME))
UNAME                   := $(patsubst MINGW64_NT-%,MSYS2,$(UNAME))

ifeq (,$(filter $(UNAME),Android Linux OpenBSD FreeBSD NetBSD DragonFly Darwin CYGWIN MSYS2))
$(error "! Your Operating System ($(UNAME)) is not supported by this Makefile")
endif

##
## Arrangement of the core
##
## The core is one shared library and everything else links against it: the frontend, the 593
## modules, the bridges and the feeds. Statically it is copied into each of them instead, and a
## module that calls input_tokenizer drags in the tokenizer, the file handling under it, and from
## there the whole of LZMA, zlib and minizip, none of which a module ever calls. That is 90 percent
## of what the release ships, the same core 603 times over.
##
## SHARED=0 builds the static arrangement instead. It is kept because it needs nothing from the
## runtime loader, so it is what to fall back to on a platform where the library misbehaves.
##

ifeq (,$(filter $(UNAME),Linux Darwin))
SHARED                  ?= 0
else
SHARED                  ?= 1
endif

# force disable LTO if DEBUG > 0
ifeq ($(shell [ $(DEBUG) -gt 0 ] && echo true),true)
override ENABLE_LTO := 0
endif

# force disable LTO if MACOS_UNIVERSAL_BINARY == 1
ifeq ($(UNAME),Darwin)
ifeq ($(MACOS_UNIVERSAL_BINARY),1)
override ENABLE_LTO := 0
endif
endif

##
## Platforms
##
## A platform is a compiler, a set of flags, a core to link against and a file name suffix. Every
## artifact belongs to exactly one of them, and for nearly every artifact the name says which:
## obj/backend.WIN.o, obj/combined.LINUX.a and hashcat.bin can be mistaken for nothing else. Their
## rules name their own compiler, so which toolchain builds them does not depend on how the build
## was asked for.
##
## A shared object is the exception. modules/module_00000.so is what a native build writes on Linux
## and it is also what make linux writes for a release, from another compiler, other flags and
## another core. Two rules claiming one file name is a tie, and make breaks a tie by taking the rule
## it read first, which has nothing to do with the goal that was asked for. That is how make linux
## came to build every module against the native core. The core library carries the same name on
## both, so a goal that needs one answers the same question, and hashcat and hashcat.bin are listed
## below for that reason rather than for a plugin of their own.
##
## So the .so name is given to a single platform per run and the goal decides. The .dll name needs no
## decision, a host that can cross compile never calls a .dll its own, and that answers the core
## library too: hashcat.dll can only have come from the WIN platform.

PLATFORMS               := NATIVE

PLUGIN_SUFFIX_NATIVE    := so
PLUGIN_SUFFIX_LINUX     := so
PLUGIN_SUFFIX_WIN       := dll

# the phony that builds every plugin of one platform: modules, modules_linux, modules_win
PHONY_SUFFIX_NATIVE     :=
PHONY_SUFFIX_LINUX      := _linux
PHONY_SUFFIX_WIN        := _win

ifneq (,$(filter $(UNAME),CYGWIN MSYS2))
PLUGIN_SUFFIX_NATIVE    := dll
endif

PLUGIN_PLATFORMS        := NATIVE

# cross compilation is offered on Linux and macOS only

ifneq (,$(filter $(UNAME),Linux Darwin))
PLATFORMS               += LINUX WIN

SO_GOALS_NATIVE         := default hashcat modules bridges feeds
SO_GOALS_NATIVE         += install install_library install_modules install_bridges install_feeds
SO_GOALS_LINUX          := binaries linux hashcat.bin modules_linux bridges_linux feeds_linux

GOALS_NATIVE            := $(filter $(SO_GOALS_NATIVE),$(MAKECMDGOALS))
GOALS_LINUX             := $(filter $(SO_GOALS_LINUX),$(MAKECMDGOALS))

ifneq (,$(GOALS_LINUX))
ifneq (,$(GOALS_NATIVE))
$(error ! Cannot build "$(GOALS_NATIVE)" and "$(GOALS_LINUX)" in one run, their shared objects claim the same file names. Please ask for them one after the other)
endif
PLUGIN_PLATFORMS        := LINUX
endif

PLUGIN_PLATFORMS        += WIN
endif

# and the way back, from a shared object file name to the platform that owns it. A suffix claimed
# twice is the tie this section exists to prevent, so it stops the build instead of being resolved by
# the order the rules happen to be read in.

$(foreach P,$(PLUGIN_PLATFORMS), \
  $(if $(PLUGIN_PLATFORM_$(PLUGIN_SUFFIX_$(P))), \
    $(error ! $(P) and $(PLUGIN_PLATFORM_$(PLUGIN_SUFFIX_$(P))) both claim the .$(PLUGIN_SUFFIX_$(P)) name), \
    $(eval PLUGIN_PLATFORM_$(PLUGIN_SUFFIX_$(P)) := $(P))))

# the platforms whose core is a shared library rather than an archive. At most two, because the
# library carries the plugin suffix of its platform, and each of those suffixes has just been given
# to a single platform.

ifeq ($(SHARED),1)
SHARED_PLATFORMS        := $(PLUGIN_PLATFORM_so) $(PLUGIN_PLATFORM_dll)
endif

##
## Makefile flags
##

MAKEFLAGS               += -l -j 8 -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS               += -j 1
endif

# what a bare make builds. Said here rather than left to whichever rule happens to be read first,
# because the plugin fragments are read before the rules of this file and one of them declaring a
# rule would otherwise decide it

.DEFAULT_GOAL           := default

##
## Do not modify
##

MODULE_INTERFACE_VERSION := 720
BRIDGE_INTERFACE_VERSION := 720
FEEDS_INTERFACE_VERSION  := 720

##
## Toolchains
##
## One block per platform, and nothing outside these blocks names a compiler.
##

CC                      := gcc
CXX                     := g++
AR                      := ar
FIND                    := find
INSTALL                 := install
RM                      := rm
SED                     := sed
SED_IN_PLACE            := -i

IS_APPLE_SILICON        := 0

ifeq ($(UNAME),Darwin)
CC                      := clang
CXX                     := clang++
# if available using llvm-ar else ar
AR                      := $(shell which llvm-ar >/dev/null 2>&1 && echo llvm-ar || echo ar)
# the sed -i option of macOS requires a parameter for the backup file (we just use "")
SED                     := /usr/bin/sed
SED_IN_PLACE            := -i ""
DARWIN_VERSION          := $(shell uname -r | cut -d. -f1)
IS_APPLE_SILICON        := $(shell [ "$$(sysctl -in hw.optional.arm64 2>/dev/null)" = "1" ] && echo 1 || echo 0)
endif

IS_AARCH64              := $(shell [ "$$(arch 2>/dev/null)" = "aarch64" ] && echo 1 || echo 0)
IS_ARM                  := $(or $(filter 1,$(IS_APPLE_SILICON)),$(filter 1,$(IS_AARCH64)))
IS_PPC                  := $(shell uname -m | grep -q -E '^(ppc|powerpc)' && echo 1 || echo 0)

ifneq (,$(filter $(UNAME),OpenBSD FreeBSD NetBSD DragonFly))
CC                      := cc
CXX                     := c++
SED                     := gsed
endif

ifeq ($(UNAME),NetBSD)
CC                      := gcc
CXX                     := g++
AR                      := gcc-ar
endif

# CC, CXX and AR keep their conventional names because that is what a builder overrides on the
# command line. Under the platform name they are what every rule below asks for.

CC_NATIVE               := $(CC)
CXX_NATIVE              := $(CXX)
AR_NATIVE               := $(AR)

ifneq (,$(filter LINUX,$(PLATFORMS)))

CC_LINUX                := gcc
CXX_LINUX               := g++
AR_LINUX                := ar

CC_WIN                  := x86_64-w64-mingw32-gcc
CXX_WIN                 := x86_64-w64-mingw32-g++
AR_WIN                  := x86_64-w64-mingw32-ar

# See BUILD_WSL.md to make these
WIN_ICONV               := /opt/win-iconv-64
WIN_PYTHON              := /opt/win-python

endif

CC_NATIVE_CLANG         := 0
CC_LINUX_CLANG          := 0
CC_WIN_CLANG            := 0

ifneq (,$(findstring clang, $(CC_NATIVE)))
CC_NATIVE_CLANG         := 1
endif

ifneq (,$(findstring clang, $(CC_LINUX)))
CC_LINUX_CLANG          := 1
endif

ifneq (,$(findstring clang, $(CC_WIN)))
CC_WIN_CLANG            := 1
endif

# force disable LTO if we are on a native build and CC == clang and OS is MSYS2 or NetBSD or DragonFly
ifeq ($(PLUGIN_PLATFORM_so),NATIVE)
ifeq ($(CC_NATIVE_CLANG),1)
ifneq (,$(filter MSYS2 NetBSD DragonFly,$(UNAME)))
override ENABLE_LTO := 0
endif
endif
endif

# force disable LTO if MSYS2 and CC is clang
ifeq ($(UNAME),MSYS2)
ifeq ($(CC_NATIVE_CLANG),1)
override ENABLE_LTO     := 0
endif
endif

ifeq ($(DEBUG),1)
$(info "## Detected Operating System : $(UNAME)")
$(info "## Detected Plugin Platforms : $(PLUGIN_PLATFORMS)")
$(info "## Detected CC : $(CC)")
$(info "## Detected CXX : $(CXX)")
endif

##
## Version
##

ifeq ($(PRODUCTION),1)
VERSION_TAG             := $(PRODUCTION_VERSION)
else
VERSION_TAG             := $(shell git describe --tags --dirty=+ || echo $(PRODUCTION_VERSION))
endif # PRODUCTION

VERSION_PURE            := $(shell echo "$(VERSION_TAG)" | $(SED) 's/.*v\([\.0-9]*\).*/\1/')
VERSION_MAJOR           := $(firstword $(subst ., ,$(VERSION_PURE)))

##
## Installation paths
##

DESTDIR                 ?=
PREFIX                  ?= /usr/local

INSTALL_FOLDER          ?= $(PREFIX)/bin
SHARED_ROOT_FOLDER      ?= $(PREFIX)/share
SHARED_FOLDER           ?= $(SHARED_ROOT_FOLDER)/hashcat
DOCUMENT_FOLDER         ?= $(SHARED_ROOT_FOLDER)/doc/hashcat
LIBRARY_FOLDER          ?= $(PREFIX)/lib
LIBRARY_DEV_ROOT_FOLDER ?= $(PREFIX)/include
LIBRARY_DEV_FOLDER      ?= $(LIBRARY_DEV_ROOT_FOLDER)/hashcat

##
## Dependencies paths
##

ifeq ($(USE_SYSTEM_LZMA),0)
DEPS_LZMA_PATH          := deps/LZMA-SDK/C
else
DEPS_LZMA_PATH          := $(LIBRARY_DEV_ROOT_FOLDER)
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
DEPS_ZLIB_PATH          := deps/zlib
else
DEPS_ZLIB_PATH          := $(LIBRARY_DEV_ROOT_FOLDER)
endif

ifeq ($(USE_SYSTEM_OPENCL),0)
DEPS_OPENCL_PATH        := deps/OpenCL-Headers
else
DEPS_OPENCL_PATH        := $(LIBRARY_DEV_ROOT_FOLDER)
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
DEPS_XXHASH_PATH        := deps/xxHash
else
DEPS_XXHASH_PATH        := $(LIBRARY_DEV_ROOT_FOLDER)
endif

ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
DEPS_UNRAR_PATH         := deps/unrar
else
DEPS_UNRAR_PATH         := $(LIBRARY_DEV_ROOT_FOLDER)
endif
endif

DEPS_SSE2NEON           := deps/sse2neon

##
## Filenames for library and frontend
##
## The soname carries the major version alone, so a plugin or a program built against any release of
## a major keeps working with every later release of that major. Under the full version it named a
## different library every point release, which would have broken every prebuilt plugin four times a
## year for a core that had not changed shape. What the plugins really depend on is narrower than the
## whole library and moves faster, and that is expressed by the version node the export contract puts
## them in rather than by the file name.
##
## A DLL carries no version in its name at all. Windows resolves an import by the file name written
## into the importer, so a name that moves is a name nothing finds, and there is no soname to say
## otherwise. hashcat.dll therefore sits beside hashcat.exe and is found with nothing set in the
## environment, which is the whole reason the package is laid out that way.
##

HASHCAT_FRONTEND        := hashcat
HASHCAT_LIBRARY_NATIVE  := libhashcat.so.$(VERSION_MAJOR)
HASHCAT_LIBRARY_LINUX   := libhashcat.so.$(VERSION_MAJOR)
HASHCAT_LIBRARY_WIN     := hashcat.dll

## What a linker resolves -lhashcat against. The runtime needs only the versioned file, because that
## is the name written into everything that links it, but a plugin built out of tree names the library
## with -l and the linker looks for the unversioned one. So the developer install adds it as a link
## beside the library. PE has none: a plugin there names hashcat.dll and the import table records it.

HASHCAT_LIBRARY_DEV_ELF   := libhashcat.so
HASHCAT_LIBRARY_DEV_MACHO := libhashcat.dylib
HASHCAT_LIBRARY_DEV_PE    :=

ifeq ($(UNAME),Darwin)
HASHCAT_LIBRARY_NATIVE  := libhashcat.$(VERSION_MAJOR).dylib
endif # Darwin

ifeq ($(UNAME),CYGWIN)
HASHCAT_FRONTEND        := hashcat.exe
HASHCAT_LIBRARY_NATIVE  := hashcat.dll
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
HASHCAT_FRONTEND        := hashcat.exe
HASHCAT_LIBRARY_NATIVE  := hashcat.dll
endif # MSYS2

# make install and make uninstall run on this machine and touch nothing a cross build wrote

HASHCAT_LIBRARY         := $(HASHCAT_LIBRARY_NATIVE)

##
## Shared compiler and linker options
##
## Everything here is true for every platform. What is true for one of them is added to that
## platform's own set further down, and never here.
##

CFLAGS                  := $(CFLAGS)
LFLAGS                  := $(LDFLAGS)

ifeq ($(DEBUG),1)
CFLAGS                  += -fstack-usage
endif

ifeq ($(ENABLE_LTO),1)
CFLAGS                  += -flto=auto
ifeq ($(CC_NATIVE_CLANG),1)
CFLAGS                  += -Wno-unknown-warning-option
endif
LFLAGS                  += -flto=auto
ifeq ($(filter FreeBSD OpenBSD,$(UNAME)),)
LFLAGS                  += -Wno-lto-type-mismatch
endif
endif

##
## Flags that describe this machine
##
## These reach the shared sets because a native artifact wants them, and every cross set removes
## them again by name. Removing the variable rather than a hand written list of flag spellings is
## what keeps the two in step: a flag added here cannot be forgotten there.
##
## -march=native asks the compiler what the host processor is, and the answer is not always one the
## compiler will then accept. Under a hypervisor the CPUID presented to the guest can map to a
## processor name that has no 64 bit support, which the driver rejects as an unknown target CPU, and
## the build stops on a flag that was only meant to be an optimisation. Ask before using it.
##
## The question is put to the native compiler, so the answer is only good for that compiler and only
## for code that runs on this machine. It is asked on every run, including a run that builds nothing
## native, because what makes the answer safe is where it is allowed to go and not whether it was
## asked for.

ifeq ($(MAINTAINER_MODE),0)
HAVE_MARCH_NATIVE       := $(shell echo | $(CC_NATIVE) -march=native -E - >/dev/null 2>&1 && echo 1 || echo 0)
HAVE_MCPU_NATIVE        := $(shell echo | $(CC_NATIVE) -mcpu=native -E - >/dev/null 2>&1 && echo 1 || echo 0)

# The same answer, in a form a plugin can append without repeating the question. Asking once and
# then having three other files decide for themselves is how DragonFlyBSD kept failing: the main
# binary respected the probe above and every bridge that wanted -march=native did not. Empty when
# the compiler will not take the flag, so appending it is always safe.

ifeq ($(HAVE_MARCH_NATIVE),1)
MARCH_NATIVE            := -march=native -mtune=native
endif

ifeq ($(HAVE_MCPU_NATIVE),1)
MCPU_NATIVE             := -mcpu=native -mtune=native
endif

ifeq ($(UNAME),Darwin)
# a universal binary is built for two architectures at once, so it cannot be built for this one
ifeq ($(MACOS_UNIVERSAL_BINARY),0)
CFLAGS_HOST_ONLY        += $(MARCH_NATIVE)
endif
else
ifeq ($(IS_PPC),1)
CFLAGS_HOST_ONLY        += $(MCPU_NATIVE)
else
CFLAGS_HOST_ONLY        += $(MARCH_NATIVE)
endif
endif
endif

ifeq ($(UNAME),Linux)
IS_RPI                  := $(shell grep -q Raspberry /proc/cpuinfo && echo 1 || echo 0)

ifeq ($(IS_RPI),1)
CFLAGS_HOST_ONLY        += -mcpu=cortex-a72
endif
endif

# mold is a linker that lives on this machine. A cross set that wants it says so itself.

ifneq ($(UNAME),Darwin)
ifeq ($(USE_MOLD),1)
LFLAGS_HOST_ONLY        += -fuse-ld=mold
endif
endif

CFLAGS                  += $(CFLAGS_HOST_ONLY)
LFLAGS                  += $(LFLAGS_HOST_ONLY)

ifeq ($(PRODUCTION),0)
CFLAGS                  += -W
CFLAGS                  += -Wall
CFLAGS                  += -Wextra
endif

## because LZMA SDK
ifeq ($(or $(filter 1,$(CC_NATIVE_CLANG)),$(filter cc,$(CC))),1)
CFLAGS                  += -Wno-typedef-redefinition
endif

ifeq ($(USE_SYSTEM_LZMA),0)
CFLAGS_LZMA             += -D_7ZIP_ST
ifeq ($(CC_NATIVE_CLANG),0)
CFLAGS_LZMA             += -Wno-misleading-indentation
endif
endif

## because ZLIB
ifeq ($(USE_SYSTEM_ZLIB),0)
CFLAGS_ZLIB             += -Wno-implicit-fallthrough
CFLAGS_ZLIB             += -Wno-implicit-function-declaration
CFLAGS_ZLIB             += -Wno-unused-parameter
CFLAGS_ZLIB             += -DIOAPI_NO_64
CFLAGS_ZLIB             += -DUNZ_BUFSIZE=262144
ifeq ($(CC_NATIVE_CLANG),1)
CFLAGS_ZLIB             += -Wno-deprecated-non-prototype -Wno-unknown-warning-option
endif
endif

## because UNRAR
ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
ifeq ($(UNAME),Darwin)
CFLAGS_UNRAR            += -std=c++14
endif
ifeq ($(CC_NATIVE_CLANG),0)
ifeq ($(filter FreeBSD OpenBSD,$(UNAME)),)
CFLAGS_UNRAR            += -Wno-class-memaccess
endif
CFLAGS_UNRAR            += -Wno-misleading-indentation
ifneq ($(UNAME),OpenBSD)
CFLAGS_UNRAR            += -Wno-format-overflow
endif
else
ifeq ($(IS_APPLE_SILICON),0)
ifneq ($(filter $(UNAME),FreeBSD OpenBSD NetBSD DragonFly),$(UNAME))
## -Wno-nontrivial-memcall names a warning that older clang does not have, and an unknown -Wno- name
## is itself a warning, once per file compiled. The two travel together so that naming a warning the
## compiler may not know costs nothing.
CFLAGS_UNRAR            += -Wno-unknown-warning-option
CFLAGS_UNRAR            += -Wno-nontrivial-memcall
endif
endif
endif
CFLAGS_UNRAR            += -Wno-missing-braces
CFLAGS_UNRAR            += -Wno-unused-variable
CFLAGS_UNRAR            += -Wno-unused-parameter
CFLAGS_UNRAR            += -Wno-unused-function
CFLAGS_UNRAR            += -Wno-sign-compare
CFLAGS_UNRAR            += -Wno-dangling-else
CFLAGS_UNRAR            += -Wno-switch
CFLAGS_UNRAR            += -Wno-parentheses
CFLAGS_UNRAR            += -Wno-implicit-fallthrough
CFLAGS_UNRAR            += -Wno-extra
CFLAGS_UNRAR            += -Wno-unknown-pragmas
CFLAGS_UNRAR            += -Wno-unused-but-set-variable
CFLAGS_UNRAR            += -Wno-deprecated-declarations
#Not supported on macOS 12.3
#CFLAGS_UNRAR            += -Wno-format-overflow
#Added hashcat 7.0.0
#CFLAGS_UNRAR            += -Wno-class-memaccess
CFLAGS_UNRAR            += -Wno-misleading-indentation
endif
endif

ifeq ($(DEBUG),0)
CFLAGS                  += -O2 -fomit-frame-pointer

# a release carries no debug information. Build with DEBUG=1 to get it, and that build is not
# stripped, so the information stays where the program is.

ifneq ($(UNAME),Darwin)
ifeq ($(and $(filter MSYS2,$(UNAME)),$(filter 1,$(CC_NATIVE_CLANG))),)
CFLAGS                  += -fno-plt
endif
ifeq ($(and $(filter DragonFly,$(UNAME)),$(filter 1,$(CC_NATIVE_CLANG))),)
LFLAGS                  += -s
endif
endif
else
ifeq ($(DEBUG),1)
ifneq ($(UNAME),Darwin)
CFLAGS                  += -DDEBUG -Og -ggdb
else
CFLAGS                  += -DDEBUG -O0 -ggdb
endif
else
ifeq ($(DEBUG),2)
ifneq ($(UNAME),Darwin)
CFLAGS                  += -DDEBUG -Og -ggdb
else
CFLAGS                  += -DDEBUG -O0 -ggdb
endif
CFLAGS                  += -fsanitize=address -fno-omit-frame-pointer
endif
endif
endif

CFLAGS                  += -pipe -Iinclude/ -IOpenCL/

# LZMA
CFLAGS                  += -I$(DEPS_LZMA_PATH)
ifeq ($(USE_SYSTEM_LZMA),1)
LFLAGS                  += -llzmasdk
endif

# ZLIB
CFLAGS                  += -I$(DEPS_ZLIB_PATH) -I$(DEPS_ZLIB_PATH)/contrib
ifeq ($(USE_SYSTEM_ZLIB),1)
LFLAGS                  += -lz -lminizip
endif

# OpenCL
CFLAGS                  += -I$(DEPS_OPENCL_PATH)

# brain
ifeq ($(ENABLE_BRAIN),1)
CFLAGS                  += -DWITH_BRAIN
endif

# xxHash. The two feeds that hash with it include it inline and need only the header. The brain is
# the one part of the core that calls the library, so the library is asked for when the brain is
# built and not otherwise, which is the same condition the vendored object is compiled under.

CFLAGS                  += -I$(DEPS_XXHASH_PATH)
ifeq ($(ENABLE_BRAIN),1)
ifeq ($(USE_SYSTEM_XXHASH),1)
LFLAGS                  += -lxxhash
endif
endif

# CUDA binary cache
ifeq ($(ENABLE_CUBIN),1)
CFLAGS                  += -DWITH_CUBIN
endif

# unrar
ifeq ($(ENABLE_UNRAR),1)
CFLAGS                  += -I$(DEPS_UNRAR_PATH)
# UnRAR is C++ and everything that links it needs the runtime named, which is the C++ standard library
# the system's own compiler uses: libc++ where clang is the system compiler and libstdc++ where gcc is.
# FreeBSD, NetBSD and DragonFly fell through this without naming one, so on those systems the single
# module that calls UnRAR, 23800, was linked short of what it needs. Nothing said so until a plugin was
# actually loaded, because a lazily bound symbol nobody calls costs nothing.

ifeq ($(UNAME),OpenBSD)
LFLAGS                  += -lc++
else
ifeq ($(UNAME),FreeBSD)
LFLAGS                  += -lc++
else
ifeq ($(UNAME),DragonFly)
LFLAGS                  += -lc++
else
ifeq ($(UNAME),NetBSD)
LFLAGS                  += -lstdc++
else
ifeq ($(UNAME),Darwin)
LFLAGS                  += -lstdc++
else
ifeq ($(UNAME),MSYS2)
LFLAGS                  += -lstdc++
else
ifeq ($(UNAME),Linux)
LFLAGS                  += -lstdc++
endif
endif
endif
endif
endif
endif
endif
endif

# Under SHARED=0 the core is copied into each artifact and nothing crosses a library boundary, so the
# export macros in include/export.h are empty there. This is on the shared flags rather than on the
# core's, because a plugin reads the same headers and has to read them the same way.

ifeq ($(SHARED),0)
CFLAGS                  += -DHC_CORE_STATIC
endif

# CCFLAGS only for C compiler
CCFLAGS                 := -std=gnu99

# CXXFLAGS only for C++ compiler
CXXFLAGS                :=

##
## Flags of the NATIVE platform
##

ifeq ($(UNAME),Android)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -D__ANDROID__
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -ldl
LFLAGS_NATIVE           += -lrt
LFLAGS_NATIVE           += -lm
LFLAGS_NATIVE           += -liconv
LFLAGS_NATIVE           += -L$(PREFIX)/lib
$(info Android environment detected.)
else ifeq ($(UNAME),Linux)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -ldl
LFLAGS_NATIVE           += -lrt
LFLAGS_NATIVE           += -lm
endif # Linux

# the ports collections build a package for a machine that is not this one, and pass the flags they
# want through the environment. Where PORTNAME is set the flags are left exactly as they arrived.

ifneq (,$(filter $(UNAME),FreeBSD DragonFly))
ifndef PORTNAME
CFLAGS_NATIVE           := $(CFLAGS)
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -L /usr/local/lib
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -lm
LFLAGS_NATIVE           += -liconv
endif
endif # FreeBSD

ifeq ($(UNAME),OpenBSD)
ifndef PORTNAME
CFLAGS_NATIVE           := $(CFLAGS)
#CFLAGS_NATIVE           += -I /ram/usr/local/include
CFLAGS_NATIVE           += -I /usr/local/include
LFLAGS_NATIVE           := $(LFLAGS)
#LFLAGS_NATIVE           += -L /ram/usr/local/lib
LFLAGS_NATIVE           += -L /usr/local/lib
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -lm
LFLAGS_NATIVE           += -liconv
endif
endif # OpenBSD

ifeq ($(UNAME),NetBSD)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -I /usr/pkg/include
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -L /usr/pkg/lib
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -lm
LFLAGS_NATIVE           += -liconv
endif # NetBSD

ifeq ($(UNAME),Darwin)
export MACOSX_DEPLOYMENT_TARGET=15.0
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -DWITH_HWMON

ifeq ($(shell test $(DARWIN_VERSION) -le 15; echo $$?), 0)
CFLAGS_NATIVE           += -DMISSING_CLOCK_GETTIME
endif

LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -framework CoreFoundation
LFLAGS_NATIVE           += -framework CoreGraphics
LFLAGS_NATIVE           += -framework Foundation
LFLAGS_NATIVE           += -framework IOKit
LFLAGS_NATIVE           += -framework Metal
LFLAGS_NATIVE           += -lIOReport
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -liconv

ifeq ($(MACOS_UNIVERSAL_BINARY),1)
ifeq ($(IS_APPLE_SILICON),1)
CFLAGS_NATIVE           += -arch arm64
CFLAGS_NATIVE           += -arch x86_64
ifeq ($(SHARED),1)
LFLAGS_NATIVE           += -arch arm64
LFLAGS_NATIVE           += -arch x86_64
endif
endif
endif

endif # Darwin

ifeq ($(IS_ARM),1)
CFLAGS_NATIVE           += -DSSE2NEON_SUPPRESS_WARNINGS
CFLAGS_NATIVE           += -I$(DEPS_SSE2NEON)
endif

ifeq ($(UNAME),CYGWIN)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpsapi
LFLAGS_NATIVE           += -liconv
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpsapi
LFLAGS_NATIVE           += -liconv
LFLAGS_NATIVE           += -lws2_32
LFLAGS_NATIVE           += -lpowrprof
endif # MSYS2

# A core object is linked into shared objects, so it is compiled position independent. The two cross
# sets carry -fPIC of their own because they are also the flags their frontend is compiled with. The
# native set is not, so the native object rule is where it is added.

CFLAGS_PIC_NATIVE       := -fpic

##
## What leaves the core, and what leaves a plugin
##
## The core defines 2,766 names and offers 1,033 of them. Which ones is said in the declaration of
## each, with HC_API or HC_PLUGIN_API out of include/export.h, and nowhere else.
## -fvisibility=hidden is what makes that true rather than decorative: a name is private unless its
## declaration says otherwise, so a plugin that reaches for anything else does not link and the error
## names the symbol. The vendored dependencies are compiled the same way, which is why LZMA, zlib,
## minizip, xxHash and unrar are inside the core and are not part of what it offers.
##
## Two names get out that nobody declared, _ZTI8RAR_EXIT and _ZTS8RAR_EXIT, so the library's table
## holds 1,035. They are the C++ type description of the value UnRAR throws and catches inside
## itself, and the compiler gives the type description of a thrown type default visibility whatever
## it is asked for, so there is nothing to write in the source that would stop it. They are the whole
## of the difference between what the contract says and what the library exports.
##
## HC_CORE_BUILD says the core is being compiled rather than something that calls it. PE has no
## visibility, so there the two macros are dllexport on one side of that answer and dllimport on the
## other, and this is how a header knows which side it is being read from.
##
## HC_CORE_STATIC says there is no library. Under SHARED=0 the core is copied into each artifact,
## nothing crosses a boundary, and the two API macros are empty: a static module still exports its
## entry point and nothing else.
##
## HC_PLUGIN_ABI_VERSION is on the core's line and on every plugin's line, and says which plugin
## interface the artifact was built against. The core defines the one name that carries the number
## and every plugin holds a reference to it, so a plugin built against an interface that has moved is
## refused by the loader by name. The frontend is given neither and takes no part in it.

CFLAGS_ABI              := -DHC_PLUGIN_ABI_VERSION=$(MODULE_INTERFACE_VERSION)

CFLAGS_CORE             := -fvisibility=hidden
CFLAGS_CORE             += -DHC_CORE_BUILD
CFLAGS_CORE             += $(CFLAGS_ABI)

##
## Flags of the LINUX and WIN platforms
##
## A release binary runs on a machine nobody here has seen. These two sets start from the shared
## flags with everything that describes this machine taken back out, and they are not derived from
## the native set, which carries decisions that are true for this box alone.
##

ifneq (,$(filter LINUX,$(PLATFORMS)))

CFLAGS_LINUX            := $(filter-out $(CFLAGS_HOST_ONLY),$(CFLAGS))
CFLAGS_LINUX            += -fPIC
CFLAGS_LINUX            += -DWITH_HWMON

ifeq ($(CC_LINUX_CLANG),1)
CFLAGS_LINUX            += -Wno-typedef-redefinition
CFLAGS_LINUX            += -Wno-unknown-warning-option
endif

ifeq ($(IS_ARM),1)
CFLAGS_LINUX            += -DSSE2NEON_SUPPRESS_WARNINGS
CFLAGS_LINUX            += -I$(DEPS_SSE2NEON)
endif

CFLAGS_WIN              := $(filter-out $(CFLAGS_HOST_ONLY),$(CFLAGS))
CFLAGS_WIN              += -fPIC
CFLAGS_WIN              += -I$(WIN_ICONV)/include/
CFLAGS_WIN              += -DWITH_HWMON

# clang is one compiler for every target and has to be told which one it is building for. A cross gcc
# is a compiler for a single target and needs nothing said. The flag is kept in a variable of its own
# because a link that compiles no source needs it just as much, and there is one of those below.

TARGET_NATIVE           :=
TARGET_LINUX            :=
TARGET_WIN              :=

ifeq ($(CC_WIN_CLANG),1)
TARGET_WIN              := --target=x86_64-w64-mingw32
CFLAGS_WIN              := $(filter-out -fno-plt,$(CFLAGS_WIN))
CFLAGS_WIN              += $(TARGET_WIN)
CFLAGS_WIN              += -D_CLANG_DISABLE_CRT_DEPRECATION_WARNINGS
CFLAGS_WIN              += -D__INTRINSIC_DEFINED___cpuidex=1
CFLAGS_WIN              += -D__INTRINSIC_DEFINED__xgetbv=1
CFLAGS_WIN              += -Wno-typedef-redefinition
CFLAGS_WIN              += -Wno-ignored-attributes
CFLAGS_WIN              += -Wno-unknown-warning-option
endif

ifeq ($(UNAME),Darwin)
CFLAGS_WIN              := $(filter-out -Wno-typedef-redefinition,$(CFLAGS_WIN))
endif

LFLAGS_LINUX            := $(filter-out $(LFLAGS_HOST_ONLY),$(LFLAGS))
LFLAGS_LINUX            += -lpthread
LFLAGS_LINUX            += -ldl
LFLAGS_LINUX            += -lm
LFLAGS_LINUX            += -static-libgcc

# The C++ runtime goes INTO the library, for the same reason it goes into the Windows binaries and by
# the same means. The archive is named directly because -static-libstdc++ only governs the libstdc++
# the driver adds by itself, and the unrar block above puts an explicit -lstdc++ on the line. Without
# this the released tree needs a libstdc++.so.6 on the target machine, which it never did before: the
# C++ in unrar used to sit in module_23800 alone, and now it sits in the core everything links to.

ifeq ($(CC_LINUX_CLANG),1)
LFLAGS_LINUX            += -stdlib=libc++
else
LFLAGS_LINUX            := $(filter-out -lstdc++,$(LFLAGS_LINUX))
LFLAGS_LINUX            += -l:libstdc++.a
LFLAGS_LINUX            += -static-libstdc++
endif

ifeq ($(USE_MOLD),1)
LFLAGS_LINUX            += -fuse-ld=mold
else
ifeq ($(ENABLE_LTO),1)
ifeq ($(CC_LINUX_CLANG),1)
LFLAGS_LINUX            += -fuse-ld=lld
else
LFLAGS_LINUX            += -fuse-ld=gold
endif
endif
endif

LFLAGS_WIN              := $(filter-out $(LFLAGS_HOST_ONLY),$(LFLAGS))

# The C++ runtime goes INTO the binary that needs it, because no runtime DLL is shipped beside them.
# Only module_23800 references any C++ at all, through unrar, so it was the one binary in the package
# importing libstdc++-6.dll, and LoadLibrary failed on every Windows machine that did not happen to
# have one on the search path. A module that references no C++ links nothing extra and does not grow.
#
# The static archive is named directly rather than asking for -static-libstdc++. That flag only governs
# the libstdc++ a driver adds by itself, so it cannot override an explicit -lstdc++, and clang reports
# it as an unused argument and links the import library anyway.
#
# The explicit one arrives here in LFLAGS, from the unrar block, so it has to be taken back out. Naming
# the archive while it is still on the line links both, and then every symbol in libsupc++ is defined
# twice and lld stops.

ifneq ($(UNAME),Darwin)
LFLAGS_WIN              := $(filter-out -lstdc++,$(LFLAGS_WIN))
LFLAGS_WIN              += -l:libstdc++.a
endif

LFLAGS_WIN              += -lpsapi
LFLAGS_WIN              += -lws2_32
LFLAGS_WIN              += -lpowrprof

ifeq ($(CC_WIN_CLANG),0)
LFLAGS_WIN              += -static
endif
LFLAGS_WIN              += -static-libgcc
ifeq ($(CC_WIN_CLANG),0)
LFLAGS_WIN              += -static-libstdc++
endif
LFLAGS_WIN              += -lole32 -loleaut32 -lwbemuuid

ifeq ($(ENABLE_LTO),1)
ifeq ($(CC_WIN_CLANG),1)
LFLAGS_WIN              += -fuse-ld=lld
LFLAGS_WIN              += -Wl,--stack,0x200000
endif
endif

endif

##
## Hardening
##
## What a developer sees on their own machine is not what the release ships. A native build on
## Ubuntu comes out with a stack protector, fortified string functions, control flow marks and a
## build id, and none of that is asked for here: it is in the distribution's gcc spec. The release
## is cross compiled with a toolchain that has no such spec, so the shipped 7.1.2 binaries carry
## partial RELRO, no BIND_NOW and no build id, and are weaker than anything anybody tests. Naming
## the flags here is what makes the two the same build.
##
## It is not decoration. hashcat reads hash files, wordlists and archive formats that came from
## somewhere else, in C, and the stack buffer overflow in mangle_dupeblock_prepend is reached by one
## rule and one word: a word of 128 characters ending in X, through -j /Xyp, asks for 127 bytes into
## a buffer of 100. With none of these flags the run writes 27 bytes past it, prints its candidate
## and exits 0. With -D_FORTIFY_SOURCE=3 the same input stops inside the memcpy and the process
## takes SIGABRT. A stack protector alone does not catch that one, the overflow lands in the
## neighbouring locals and never reaches the canary, which is why both are here rather than either.
##
## Each compiler is asked whether it takes the set before the set is used. These are the flags that
## stop a build outright on a platform that does not have them: -fcf-protection is an error on
## anything that is not x86, and -fstack-clash-protection is an error on several targets clang
## otherwise supports. The set is asked as one question and only taken apart when the answer is no,
## so the usual cost is a single compiler run per platform.
##

## A flag can also be taken and then ignored, which is not the same answer and which clang says with
## an unused argument warning. That is what put -fstack-clash-protection on every Windows compile
## line: the question was asked of clang with no target named, where the flag is real, and the answer
## was then used for a mingw target where it is not. So the question is asked with the platform's own
## target, and where the compiler is clang, a flag it accepts and ignores counts as an answer of no.
## Only clang is asked that way, because -Werror=unused-command-line-argument is a flag gcc does not
## have, and asking gcc with it would fail every question.

CC_STRICT                = $(if $(filter 1,$(CC_$(1)_CLANG)),-Werror=unused-command-line-argument)

cc_takes                 = $(shell echo 'int main (void) { return 0; }' | $(1) -O2 $(2) -c -x c - -o /dev/null >/dev/null 2>&1 && echo ok)
cc_filter                = $(if $(call cc_takes,$(1),$(2)),$(2),$(foreach F,$(2),$(if $(call cc_takes,$(1),$(F)),$(F))))

## $(1) platform. What the question has to be asked with for the answer to be worth anything.

cc_asks                  = $(CC_$(1)) $(TARGET_$(1)) $(call CC_STRICT,$(1))

HARDEN_TRY              := -fstack-protector-strong -fstack-clash-protection -fcf-protection=full

$(foreach P,$(PLATFORMS),$(eval HARDEN_CFLAGS_$(P) := $(call cc_filter,$(call cc_asks,$(P)),$(HARDEN_TRY))))

# on PE the stack protector is two functions out of libssp, and a linker offered both forms of that
# library takes the import one, so the binary comes out needing libssp-0.dll. That DLL belongs to a
# mingw installation, it is not shipped beside hashcat and no Windows machine has one, so the binary
# would fail to load. Naming the archive puts the two functions inside it instead. A cross gcc links
# the whole runtime statically already and takes this as a no-op.

ifneq (,$(filter WIN,$(PLATFORMS)))
ifneq (,$(findstring -fstack-protector,$(HARDEN_CFLAGS_WIN)))
LFLAGS_WIN              += -l:libssp.a
endif
endif

# a fortified string function is one the optimiser can size the buffer of, so it needs a build that
# optimises. -U comes first because a distribution spec may have defined it already, and redefining
# it is a warning on every translation unit in the tree.

ifeq ($(DEBUG),0)
$(foreach P,$(PLATFORMS),$(eval HARDEN_CFLAGS_$(P) += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3))
endif

##
## The link side is a property of the object format rather than of the compiler.
##
## ELF: the relocations are made read only and bound before main, so a write through a stray pointer
## cannot reach a function pointer the loader still owns, and the build id is the name a crash report
## and a separated debug file are matched by.
##
## PE: the three characteristics bits. All three are what this linker sets by itself today, measured
## at 0x0160 on a binary linked with no flags at all, and they are asked for anyway so that the
## answer does not change when the linker does.
##
## Mach-O: neither applies. ld64 has no -z options and writes a UUID of its own accord.
##

HARDEN_LFLAGS_ELF       := -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--build-id=sha1
HARDEN_LFLAGS_PE        := -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va
HARDEN_LFLAGS_MACHO     :=

# the frontend is the one artifact that is not already position independent. Everything else is a
# shared object and is compiled -fpic to be one.

HARDEN_FRONTEND_ELF     := -fPIE -pie
HARDEN_FRONTEND_PE      :=
HARDEN_FRONTEND_MACHO   :=

FORMAT_NATIVE           := ELF
FORMAT_LINUX            := ELF
FORMAT_WIN              := PE

ifeq ($(UNAME),Darwin)
FORMAT_NATIVE           := MACHO
endif

ifneq (,$(filter $(UNAME),CYGWIN MSYS2))
FORMAT_NATIVE           := PE
endif

$(foreach P,$(PLATFORMS),$(eval HARDEN_LFLAGS_$(P)   := $(HARDEN_LFLAGS_$(FORMAT_$(P)))))
$(foreach P,$(PLATFORMS),$(eval HARDEN_FRONTEND_$(P) := $(HARDEN_FRONTEND_$(FORMAT_$(P)))))

# the PE characteristics were never given to clang's driver, and this section is not the place to
# find out whether they can be

ifeq ($(CC_WIN_CLANG),1)
HARDEN_LFLAGS_WIN       :=
endif

$(foreach P,$(PLATFORMS),$(eval CFLAGS_$(P) += $(HARDEN_CFLAGS_$(P))))
$(foreach P,$(PLATFORMS),$(eval LFLAGS_$(P) += $(HARDEN_LFLAGS_$(P))))

##
## Reproducibility
##
## Three things in a build move on their own, and all three end up inside what ships: the moment it
## happened, the name of the checkout it happened in, and the directory it happened in. Two builds of
## one commit are then different bytes, and nobody can check that a release was built from the source
## it says it was.
##
## The first two are pinned by asking, so that a developer build carries on being told apart from the
## one before it. SOURCE_DATE_EPOCH is the convention for a build timestamp and is taken from the
## environment when it is set. VERSION_TAG is already overridable from the command line, and
## PRODUCTION=1 pins it to the release version, so a reproducible release is make PRODUCTION=1 with
## SOURCE_DATE_EPOCH set and nothing else.
##
## COMPTIME is also the first element of the kernel cache key, and pinning it used to mean an edited
## .cl file was never recompiled, because the key said nothing about the source. The key carries a
## digest of the kernel that is compiled and a digest of every other file in the kernel directory
## now, so it turns over when the kernels do and not when the frontend happens to be relinked.
##
## The third is pinned always, because there is no reason for it ever to be there. -ffile-prefix-map
## rewrites the build directory to a dot wherever the compiler would have written it out, which is
## the debug information and __FILE__. Without it the debug files name whoever built them and their
## home directory, and two builds of one commit in two directories differ.
##
## The PE header carries a timestamp that no compiler flag reaches, and it was the only thing left
## differing between two Windows builds. Nothing reads it here, so it is turned off rather than
## pinned.
##

COMPTIME                := $(or $(SOURCE_DATE_EPOCH),$(shell date +%s))

REPRO_TRY               := -ffile-prefix-map=$(CURDIR)=.

$(foreach P,$(PLATFORMS),$(eval CFLAGS_$(P) += $(call cc_filter,$(call cc_asks,$(P)),$(REPRO_TRY))))

REPRO_LFLAGS_ELF        :=
REPRO_LFLAGS_PE         := -Wl,--no-insert-timestamp
REPRO_LFLAGS_MACHO      :=

$(foreach P,$(PLATFORMS),$(eval LFLAGS_$(P) += $(REPRO_LFLAGS_$(FORMAT_$(P)))))

##
## Plugins
##
## A plugin is a module, a bridge or a feed. Nothing registers it: src/modules/module_*.c is a
## wildcard, so a file dropped in there is built on the next make, and the number in its name is the
## hash mode it answers to. 80000 upwards is reserved for private and third party modules and
## nothing upstream will ever take those numbers.
##
## What is built out of it is modules/module_NNNNN.so, and hashcat loads it by that name when the
## user asks for that hash mode. It links against the core library rather than carrying a copy, so
## the functions it calls out of hashcat, the tokenizer and the conversion helpers and the host side
## hash and cipher entry points, are resolved at load time out of one library that is already in
## memory.
##
## Two things are true of a built plugin and both are enforced rather than documented. It exports
## exactly one name, its entry point, because everything else is hidden. And it holds a reference to
## a name carrying the plugin interface version it was compiled against, so a plugin built for an
## older hashcat is refused by the loader with a message saying which version it wanted, instead of
## loading and then misbehaving.
##
## You do not need this tree to build a plugin. make install_library_dev installs the headers the
## plugin interface is declared in, and a plugin built against those and the core library alone works
## the same. That is the supported way to keep a plugin in its own repository.
##

##
## The flags a plugin is compiled with
##
## A plugin is glue. A module says what a hash mode looks like, decodes a hash line and hands every
## byte of real work to the core, and the two modules in the tree that carry a hook body spend it
## inside the core as well. So the flags that describe this machine buy a plugin nothing, and asking
## the compiler to tune 593 shared objects for the host processor is close to a third of the build
## for code that is not in a loop.
##
## The core keeps them, because there they are worth something. The rule engine runs 5.90 s over
## 240 million candidates through --stdout with them and 7.77 s without, and almost all of that is
## -mtune: the same measurement at -march=x86-64-v3 is 7.64 s. That is a property of the processor
## the build is running on, so it stays on the platform that is that processor and reaches no
## release. The two cross sets never had these flags.
##
## A bridge that carries a vectorised reference implementation is the exception, and it is already
## an exception: it names the instruction set it wants itself through SIMD_<P>, which is added after
## these flags and is therefore unaffected.
##

$(foreach P,$(PLATFORMS),$(eval CFLAGS_PLUGIN_$(P) := $(filter-out $(CFLAGS_HOST_ONLY),$(CFLAGS_$(P)))))

# A plugin is compiled hidden for the same reason the core is. What it hands the core is marked
# HC_PLUGIN_ENTRY in the header that declares it, and everything else it defines is its own, so a
# built plugin exports its entry point and nothing else.

$(foreach P,$(PLATFORMS),$(eval CFLAGS_PLUGIN_$(P) += -fvisibility=hidden))

##
## Flags a vendored dependency needs, per platform
##
## The warning a dependency trips over is the same everywhere, so the base is shared and only the
## platform that needs more says so.
##

CFLAGS_LZMA_NATIVE      := $(CFLAGS_LZMA)
CFLAGS_ZLIB_NATIVE      := $(CFLAGS_ZLIB)
CFLAGS_UNRAR_NATIVE     := $(CFLAGS_UNRAR)

CFLAGS_LZMA_LINUX       := $(CFLAGS_LZMA)
CFLAGS_ZLIB_LINUX       := $(CFLAGS_ZLIB)
CFLAGS_UNRAR_LINUX      := $(CFLAGS_UNRAR)

CFLAGS_LZMA_WIN         := $(CFLAGS_LZMA)
CFLAGS_ZLIB_WIN         := $(CFLAGS_ZLIB)
CFLAGS_UNRAR_WIN        := $(CFLAGS_UNRAR)

ifeq ($(UNAME),Darwin)
CFLAGS_LZMA_WIN         += -Wno-misleading-indentation

CFLAGS_UNRAR_WIN        += -Wno-misleading-indentation
CFLAGS_UNRAR_WIN        += -Wno-class-memaccess
endif

##
## The instruction set a plugin may use
##
## Three bridges carry a vectorised reference implementation and want more than the baseline. What
## more means is a property of the machine the artifact will run on, so it is answered here once per
## platform. Each of those bridges used to answer it again from UNAME, the processor and
## MAINTAINER_MODE, and the four answers drifted.
##

ifeq ($(MAINTAINER_MODE),0)
SIMD_LINUX              := -mavx2
SIMD_WIN                := -mavx2

ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),0)
SIMD_NATIVE             := -mavx2
endif
else
ifeq ($(IS_PPC),1)
SIMD_NATIVE             := $(MCPU_NATIVE)
else
SIMD_NATIVE             := $(MARCH_NATIVE)
endif
endif
endif

##
## Where an artifact looks for the core library
##
## The tree is unzipped and run from wherever it landed, so the library is found relative to whoever
## needs it: beside the frontend, one directory above every plugin. The install prefix is named as
## well, because make install puts the library somewhere the loader is not obliged to look. Nothing
## here asks the person running hashcat to set an environment variable.
##
## Windows says none of this and wants none of it. The loader searches the directory of the
## executable, hashcat.exe imports hashcat.dll, so the library is in the process before the first
## plugin is loaded and every plugin resolves it from there by name.
##
## A plugin that reaches for something the library does not carry is a link error here. Without this
## it links, and the first the user hears of it is "undefined symbol" when the plugin is dlopened, in
## the middle of a run. This is where the export contract is checked against every plugin there is.
## macOS and Windows need nothing, their linkers already refuse a shared object with a symbol it
## cannot resolve.
##

## Which of these a native build wants is decided by the format it produces and not by the name of
## the operating system. A native build on MSYS2 writes PE, where there is no run path to record and
## where -z is not an option the linker has, and reading UNAME instead is what sent both of those to
## a PE linker and stopped the build.

ifeq ($(FORMAT_NATIVE),MACHO)
LFLAGS_FRONTEND_NATIVE  := -Wl,-rpath,@loader_path -Wl,-rpath,$(LIBRARY_FOLDER)
LFLAGS_PLUGIN_NATIVE    := -Wl,-rpath,@loader_path/.. -Wl,-rpath,$(LIBRARY_FOLDER)
else ifeq ($(FORMAT_NATIVE),PE)
LFLAGS_FRONTEND_NATIVE  :=
LFLAGS_PLUGIN_NATIVE    :=
else
LFLAGS_FRONTEND_NATIVE  := -Wl,-rpath,'$$ORIGIN' -Wl,-rpath,$(LIBRARY_FOLDER)
LFLAGS_PLUGIN_NATIVE    := -Wl,-rpath,'$$ORIGIN/..' -Wl,-rpath,$(LIBRARY_FOLDER) -Wl,-z,defs
endif

LFLAGS_FRONTEND_LINUX   := -Wl,-rpath,'$$ORIGIN' -Wl,-rpath,$(LIBRARY_FOLDER)
LFLAGS_PLUGIN_LINUX     := -Wl,-rpath,'$$ORIGIN/..' -Wl,-rpath,$(LIBRARY_FOLDER) -Wl,-z,defs

##
## The core each platform links
##
## The library replaces the archive for a platform that has one. Every other platform keeps the
## archive, which is also what the whole build falls back to under SHARED=0.
##
## A plugin names the library file on its link line, the same on both. The linker reads a shared
## object for its dynamic symbols and a DLL for its export table, and writes an import of the file
## name in either case, so neither side needs a stub library of its own.
##

CORE_NATIVE             := obj/combined.NATIVE.a
CORE_LINUX              := obj/combined.LINUX.a
CORE_WIN                := obj/combined.WIN.a

$(foreach P,$(SHARED_PLATFORMS),$(eval CORE_$(P) := $(HASHCAT_LIBRARY_$(P))))

# on Apple Silicon the archive is removed before it is written, rather than updated in place
ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),1)
ARCHIVE_CLEAN_NATIVE    := $(RM) -f obj/combined.NATIVE.a
endif
endif

##
## Objects
##

EMU_OBJS_ALL            := emu_general emu_inc_common emu_inc_platform emu_inc_scalar emu_inc_simd
EMU_OBJS_ALL            += emu_inc_rp_common emu_inc_rp emu_inc_rp_optimized
EMU_OBJS_ALL            += emu_inc_hash_md4 emu_inc_hash_md5 emu_inc_hash_ripemd160 emu_inc_hash_sha1 emu_inc_hash_sha256 emu_inc_hash_sha384 emu_inc_hash_sha512 emu_inc_hash_streebog256 emu_inc_hash_streebog512 emu_inc_ecc_secp256k1 emu_inc_bignum_operations
EMU_OBJS_ALL            += emu_inc_cipher_aes emu_inc_cipher_camellia emu_inc_cipher_des emu_inc_cipher_kuznyechik emu_inc_cipher_serpent emu_inc_cipher_twofish
EMU_OBJS_ALL            += emu_inc_hash_base58

OBJS_ALL                := affinity autotune backend benchmark bitmap bitops bridges combinator common convert cpt cpu_crc32 cpu_features debugfile dispatch dynloader event ext_ADL ext_cuda ext_hip ext_nvapi ext_nvml ext_nvrtc ext_hiprtc ext_OpenCL ext_openssl ext_sysfs_amdgpu ext_sysfs_intelgpu ext_sysfs_cpu ext_lzma ext_zlib filehandling folder hashcat hashes hlfmt hwmon induct interface keyboard_layout locking logfile loopback memchr memory monitor mpsp outfile_check outfile parser path pidfile plugin_abi potfile pubkey pwpipe restore rp rp_cpu selftest slow_candidates shared status stdout straight generic system terminal thread timer tuningdb usage user_options wordlist $(EMU_OBJS_ALL)

ifeq ($(ENABLE_BRAIN),1)
OBJS_ALL                += brain
endif

CORE_OBJS_NATIVE        := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.o)
CORE_OBJS_LINUX         := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.o)
CORE_OBJS_WIN           := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.o)

ifeq ($(UNAME),Darwin)
OBJS_METAL              := ext_metal ext_iokit

CORE_OBJS_NATIVE        += $(foreach OBJ,$(OBJS_METAL),obj/$(OBJ).METAL.NATIVE.o)
endif

ifeq ($(USE_SYSTEM_LZMA),0)
OBJS_LZMA               := 7zCrc 7zCrcOpt 7zFile 7zStream Alloc Bra Bra86 BraIA64 CpuArch Delta LzmaDec Lzma2Dec MtDec Sha256 Sha256Opt Threads Xz XzCrc64 XzCrc64Opt XzDec XzIn

CORE_OBJS_NATIVE        += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LZMA.NATIVE.o)
CORE_OBJS_LINUX         += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LZMA.LINUX.o)
CORE_OBJS_WIN           += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LZMA.WIN.o)
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
OBJS_ZLIB               := adler32 crc32 deflate inflate inffast inftrees trees gzread gzwrite gzclose zutil gzlib contrib/minizip/unzip contrib/minizip/ioapi

CORE_OBJS_NATIVE        += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).ZLIB.NATIVE.o)
CORE_OBJS_LINUX         += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).ZLIB.LINUX.o)
CORE_OBJS_WIN           += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).ZLIB.WIN.o)
endif

# the brain is the only thing in the core that hashes with xxhash, so it is compiled in beside it.
# The two feeds that hash with it compile their own copy, because a feed is a plugin and xxhash is
# not something the core promises a plugin.

ifeq ($(ENABLE_BRAIN),1)
ifeq ($(USE_SYSTEM_XXHASH),0)
OBJS_XXHASH             := xxhash

CORE_OBJS_NATIVE        += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).XXHASH.NATIVE.o)
CORE_OBJS_LINUX         += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).XXHASH.LINUX.o)
CORE_OBJS_WIN           += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).XXHASH.WIN.o)
endif
endif

ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
OBJS_UNRAR              := strlist strfn pathfn smallfn global file filefn filcreat archive arcread unicode system isnt crypt crc rawread encname resource match timefn rdwrfn consio options errhnd rarvm secpassword rijndael getbits sha1 sha256 blake2s hash extinfo extract volume list find unpack headers threadpool rs16 cmddata ui filestr recvol rs scantree qopen hc_decompress_rar

CORE_OBJS_NATIVE        += $(foreach OBJ,$(OBJS_UNRAR),obj/$(OBJ).UNRAR.NATIVE.o)
CORE_OBJS_LINUX         += $(foreach OBJ,$(OBJS_UNRAR),obj/$(OBJ).UNRAR.LINUX.o)
CORE_OBJS_WIN           += $(foreach OBJ,$(OBJS_UNRAR),obj/$(OBJ).UNRAR.WIN.o)
endif
endif

##
## Plugin sources
##
## A wildcard of the names that are plugins, and not of everything that happens to sit next to them.
## src/modules also holds the four bodies that several modules share, and src/feeds two more that a
## feed includes. None of those six is a plugin, and a wildcard of the whole directory used to hand
## all six to make as things the modules and the feeds depend on.
##

MODULES_SRC             := $(wildcard src/modules/module_*.c)
BRIDGES_SRC             := $(wildcard src/bridges/bridge_*.c)
FEEDS_SRC               := $(wildcard src/feeds/feed_*.c)

BRIDGES_ALL             := $(patsubst src/bridges/%.c,%,$(BRIDGES_SRC))

MODULES_DISABLE         ?=
BRIDGES_DISABLE         ?=
FEEDS_DISABLE           ?=

ifeq ($(ENABLE_UNRAR),0)
MODULES_SRC             := $(filter-out src/modules/module_23800.c,$(MODULES_SRC))
MODULES_DISABLE         += modules/module_23800.so
MODULES_DISABLE         += modules/module_23800.dll
endif

$(MODULES_DISABLE): ;
$(BRIDGES_DISABLE): ;
$(FEEDS_DISABLE): ;

##
## Tools
##

TOOLS                   += $(wildcard tools/*hashcat.pl)
TOOLS                   += $(wildcard tools/*hashcat.py)

##
## What a plugin that needs more than its own source says about itself
##
## A fragment beside a plugin is read here, before any rule exists, and what it sets is data. It
## does not build anything itself, so a plugin cannot end up built by a command that has drifted
## away from the one every other plugin uses. With <b> the name of the bridge:
##
##   BRIDGE_SRC_<b>          every source it is built from, its own included
##   BRIDGE_CFLAGS_<b>       flags it needs on every platform
##   BRIDGE_CFLAGS_<b>_<P>   flags it needs on platform <P>, one of NATIVE, LINUX or WIN
##   BRIDGE_DEPS_<b>_<P>     prerequisites that are not compiler inputs
##   BRIDGE_SKIP_<b>_<P>     set when it cannot be built there, and then the fragment carries the
##                           rule that says why
##
## A fragment may still declare a rule of its own. An explicit rule beats the pattern rules below
## whatever order they are read in.

include $(wildcard src/modules/*.mk)
include $(wildcard src/bridges/*.mk)
include $(wildcard src/feeds/*.mk)

$(foreach B,$(BRIDGES_ALL),$(eval BRIDGE_SRC_$(B) ?= src/bridges/$(B).c))

##
## Header dependencies
##
## A rule names only the .c file, so make cannot see the headers that went into an object and used to
## link a binary built against an old one without a word. That is silent and it has cost real time: a
## struct that grew in one translation unit and not in another, and a constant that kept its old value
## after being edited. The one rule that existed covered include/*.h and nothing else, so a change to a
## header under deps/, to src/modules/scrypt_common.c or to src/feeds/feed_wordlist.h left the artifact
## it belongs to untouched.
##
## The compiler already knows the answer, so it is asked to write it down. -MMD writes the headers of
## each translation unit next to the object, -MP adds an empty rule for each of those headers so that
## deleting or renaming one does not stop make on a prerequisite it can no longer find, and the files
## are read back below.
##
## The modules, the feeds and the frontend are compiled and linked by one command, and the dependency
## file the compiler picks by itself would be named after the artifact alone. A module built natively
## and the same module cross compiled would then share one file and overwrite each other, so the name
## is given explicitly and carries the name of the platform that built it.
##
## The bridges are not covered. Some of them compile a second source in the same command, and one
## command can only write one dependency file, so it would describe the last source and quietly say
## nothing about the first. They still rebuild through the core archive they link.

DEPFLAGS                := -MMD -MP

DEPS_ALL                := $(wildcard obj/*.d obj/*/*.d obj/*/*/*.d)

-include $(DEPS_ALL)

## An interrupted or failed recipe leaves a partial file behind, and make reads the timestamp and calls
## it done on the next run. A failed ar is the one that bites, it leaves a 17 byte archive that every
## module then links against.

.DELETE_ON_ERROR:

##
## Rules: the headers a plugin is built against
##
## The API is declared in headers, so the development install ships the headers it is declared in and
## everything those include, rather than all 92. The set is asked of the compiler instead of written
## down here, out of a translation unit that includes every header the API starts from.
##
## Three things start it. The headers that carry HC_API, HC_PLUGIN_API or HC_PLUGIN_ENTRY, which is
## where the contract is written. The emulation headers, whose whole job is to hand a plugin the host
## build of a kernel header, so the macro on those declarations is written in the kernel header
## through DECLSPEC rather than here. And thread.h, which declares nothing the core exports at all:
## it is how a plugin spells a thread and a mutex on either platform, and a feed that reads ahead
## needs it.
##
## The kernel headers the set pulls in are not installed here. install_kernels already ships all of
## OpenCL/ beside the binary, and that is the directory a plugin build points at for them.
##
## The set is the closure and not the roots. types.h is the shape of everything a plugin is handed,
## and it reaches brain.h, hwmon.h, rp.h, terminal.h, user_options.h and the backend headers for the
## structs it embeds, so those are installed too and nothing compiles without them. Being installed
## is not being promised: what the core offers is decided by the macro on each declaration, so a
## plugin that calls one of the functions those headers declare compiles and then does not link.
##

API_HEADER_ROOTS        := $(shell grep -l -E '^HC_(API|PLUGIN_API|PLUGIN_ENTRY) ' include/*.h)
API_HEADER_ROOTS        += $(wildcard include/emu_inc_*.h)
API_HEADER_ROOTS        += include/thread.h

# read when the install rule expands it, so a plain build does not pay for it. The headers are read
# the way a plugin reads them, which is what the set is for, so the plugin interface version is on
# this line as well: the three headers only a plugin includes refuse to be read without it.

API_INCLUDES             = $(shell $(CC_NATIVE) $(CCFLAGS) $(CFLAGS_NATIVE) $(CFLAGS_ABI) -MM obj/api.c)

API_HEADERS              = $(sort $(filter include/%.h,$(API_INCLUDES)))

# The vendored headers the set reaches are installed with it. types.h names an LZMA type and a zlib
# handle, so a plugin that includes it needs the SDK's header and zlib's, and an install that leaves
# them out is one nothing can be built against. Which headers those are is not a decision either: it
# is the same dependency output. They are laid out under one directory the way the include paths in
# this file lay them out, so a plugin build points at that directory and finds all of it.

API_DEP_HEADERS          = $(sort $(filter deps/%.h,$(API_INCLUDES)))

API_DEP_ROOTS           := $(DEPS_ZLIB_PATH)/contrib $(DEPS_LZMA_PATH) $(DEPS_ZLIB_PATH) $(DEPS_OPENCL_PATH) $(DEPS_XXHASH_PATH)

obj/api.c: $(API_HEADER_ROOTS)
	printf '#include "common.h"\n#include "types.h"\n' > $@
	printf '#include "%s"\n' $(sort $(notdir $(API_HEADER_ROOTS))) >> $@

##
## Rules: the arrangement the tree was last built in
##
## SHARED, the plugin interface version and which platform owns the .so name decide how an artifact
## is compiled and what it is linked against. None of the three is a file, so make cannot see one
## change, and asking for a different answer left everything already built alone. A static frontend
## beside plugins that resolve out of the library, so two copies of the core in one process with a
## set of globals each. Or a release built after a native build, where the library and the plugins
## the native build wrote are newer than every release object, and make linux keeps a core compiled
## -march=native for this box. Or a raised MODULE_INTERFACE_VERSION that the core still carries the
## old number for, which is the refusal a stale plugin is supposed to meet not happening. None of
## them says a word.
##
## So the answer is written down. The file is rewritten only when the answer actually differs, so its
## timestamp is the moment the arrangement last changed, and naming it as a prerequisite is what
## makes a switch rebuild what the switch decides, objects included.
##

ARRANGEMENT             := SHARED=$(SHARED) PLUGIN_ABI=$(MODULE_INTERFACE_VERSION) PLUGINS=$(PLUGIN_PLATFORM_so)

.PHONY: FORCE
FORCE:

obj/arrangement: FORCE
	@printf '%s\n' "$(ARRANGEMENT)" | cmp -s - $@ || printf '%s\n' "$(ARRANGEMENT)" > $@

##
## Rules: the core
##
## One set per platform, from one text. Which compiler and which flags a rule uses is read out of the
## platform in the name of the object it is building.
##

define CORE_RULES

obj/%.$(1).o: src/%.c obj/arrangement
	$$(CC_$(1)) $$(CCFLAGS) $$(CFLAGS_$(1)) $$(CFLAGS_CORE) $$(DEPFLAGS) -c -o $$@ $$< $$(CFLAGS_PIC_$(1))

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.LZMA.$(1).o: $$(DEPS_LZMA_PATH)/%.c obj/arrangement
	$$(CC_$(1)) $$(CCFLAGS) $$(CFLAGS_$(1)) $$(CFLAGS_CORE) $$(CFLAGS_LZMA_$(1)) $$(DEPFLAGS) -c -o $$@ $$< $$(CFLAGS_PIC_$(1))
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
obj/%.ZLIB.$(1).o: $$(DEPS_ZLIB_PATH)/%.c obj/arrangement
	$$(CC_$(1)) $$(CCFLAGS) $$(CFLAGS_$(1)) $$(CFLAGS_CORE) $$(CFLAGS_ZLIB_$(1)) $$(DEPFLAGS) -c -o $$@ $$< $$(CFLAGS_PIC_$(1))
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
obj/%.XXHASH.$(1).o: $$(DEPS_XXHASH_PATH)/%.c obj/arrangement
	$$(CC_$(1)) $$(CCFLAGS) $$(CFLAGS_$(1)) $$(CFLAGS_CORE) $$(DEPFLAGS) -c -o $$@ $$< $$(CFLAGS_PIC_$(1))
endif

ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
obj/%.UNRAR.$(1).o: $$(DEPS_UNRAR_PATH)/%.cpp obj/arrangement
	$$(CXX_$(1)) $$(CXXFLAGS) $$(CFLAGS_$(1)) $$(CFLAGS_CORE) $$(CFLAGS_UNRAR_$(1)) $$(DEPFLAGS) -c -o $$@ $$< $$(CFLAGS_PIC_$(1))
endif
endif

obj/combined.$(1).a: $$(CORE_OBJS_$(1))
	$$(ARCHIVE_CLEAN_$(1))
	$$(AR_$(1)) rcs $$@ $$(CORE_OBJS_$(1))

endef

$(foreach P,$(PLATFORMS),$(eval $(call CORE_RULES,$(P))))

# the two Metal sources are Objective C and only ever built here, so they are outside the set above

ifeq ($(UNAME),Darwin)
obj/%.METAL.NATIVE.o: src/%.m obj/arrangement
	$(CC_NATIVE) $(CCFLAGS) $(CFLAGS_NATIVE) $(CFLAGS_CORE) $(DEPFLAGS) -c -o $@ $< $(CFLAGS_PIC_NATIVE)
endif

##
## Rules: the core as a shared library
##
## The same objects the archive is made of, and src/main.c is not one of them, so nothing that
## belongs to the command line program is inside the library.
##
## -z,defs makes a symbol the library cannot resolve a link error here rather than a dlopen failure
## on a user's machine. It found nine undefined unz* symbols on the first attempt, from the minizip
## objects in a subdirectory that the archive had been swallowing without a word. A DLL is refused
## for an undefined symbol whatever is asked, so Windows gets the same check for free, and it found
## the same minizip objects and then iconv. An archive hands out only what is asked for, so the
## iconv the wordlist reader calls had been left to the frontend to supply. The library carries it.
##
## The install_name is @rpath rather than the directory make install would write to, so the library
## is found beside the frontend in an unpacked tree and through the install prefix after an install,
## from one build. A DLL has no such field and needs none. Windows records the file name in whoever
## imports it and searches for that name from the directory of the executable.
##

LIBRARY_LFLAGS_NATIVE   := -shared
LIBRARY_LFLAGS_LINUX    := -shared
LIBRARY_LFLAGS_WIN      := -shared

ifeq ($(FORMAT_NATIVE),MACHO)
## the library is linked with the C++ driver because UnRAR is C++, and that driver names the C++
## runtime itself. Naming it a second time is a duplicate the linker reports on every build. It is
## taken out of the flags the library link uses and left in the ones the frontend and the plugins
## use, because those are linked with the C driver and do need it named.
LFLAGS_NATIVE_LIBRARY_FILTER := -lstdc++
LIBRARY_LFLAGS_NATIVE   += -install_name @rpath/$(HASHCAT_LIBRARY_NATIVE)
LIBRARY_LFLAGS_NATIVE   += -current_version $(VERSION_PURE)
LIBRARY_LFLAGS_NATIVE   += -compatibility_version $(VERSION_MAJOR)
else ifeq ($(FORMAT_NATIVE),PE)
## a DLL carries no soname, it is found by the file name written into whatever imports it
else
LIBRARY_LFLAGS_NATIVE   += -Wl,-soname,$(HASHCAT_LIBRARY_NATIVE)
LIBRARY_LFLAGS_NATIVE   += -Wl,-z,defs
endif

LIBRARY_LFLAGS_LINUX    += -Wl,-soname,$(HASHCAT_LIBRARY_LINUX)
LIBRARY_LFLAGS_LINUX    += -Wl,-z,defs

# What the core exports is what a plugin may call. It is not something a plugin may replace, and
# hashcat has no mechanism that would want it to, so a call inside the core binds to the core's own
# definition instead of going back out through the dynamic symbol table for an answer that cannot
# differ. Without this, 582 of the library's own calls are resolved through the global offset table:
# 240 million candidates through the rule engine and out to --stdout take 82.7 s that way and 80.9 s
# this way.

ifneq ($(UNAME),Darwin)
LIBRARY_LFLAGS_NATIVE   += -Wl,-Bsymbolic-functions
endif

LIBRARY_LFLAGS_LINUX    += -Wl,-Bsymbolic-functions

# the library is the one artifact linked from objects alone. Every other link rule compiles a source
# in the same command and reads the target out of the compile flags, so this is where a cross clang
# would otherwise be left aiming at the host

LIBRARY_LFLAGS_WIN      += $(TARGET_WIN)

ifneq (,$(filter LINUX,$(PLATFORMS)))
LIBRARY_INPUTS_WIN      := $(WIN_ICONV)/lib/libiconv.a
endif

##
## The plugin interface version, and how a stale plugin is refused
##
## What the core exports is decided in include/export.h and enforced by -fvisibility=hidden, so there
## is no list here and nothing to keep in step with the source. What is left to arrange is the other
## half: a plugin built against one plugin interface must not load against a core that has moved on.
##
## The core defines one name that carries MODULE_INTERFACE_VERSION, and every plugin holds a pointer
## to it. Raise the number and the name changes, so every plugin built against the old one fails to
## load and the loader says which name it could not find. This is one mechanism on all three
## platforms. ELF could express the same thing as a version node and PE cannot, and one mechanism
## that all of them understand is worth more than the extra sentence a version node would let ELF
## say.
##
## There is no flag for it. The pointer is in include/export.h, on the plugin's side of the same
## macro that names the symbol, so the link error and the load time refusal both come out of what
## the source says rather than out of an argument someone has to remember to pass.
##

## $(1) platform

define LIBRARY_RULES

$$(HASHCAT_LIBRARY_$(1)): $$(CORE_OBJS_$(1)) $$(LIBRARY_INPUTS_$(1)) obj/arrangement
	$$(CXX_$(1)) $$(CORE_OBJS_$(1)) $$(LIBRARY_INPUTS_$(1)) -o $$@ $$(filter-out $$(LFLAGS_$(1)_LIBRARY_FILTER),$$(LFLAGS_$(1))) $$(LIBRARY_LFLAGS_$(1))

endef

$(foreach P,$(SHARED_PLATFORMS),$(eval $(call LIBRARY_RULES,$(P))))

##
## Rules: the frontend
##
## $(1) platform, $(2) dependency file, $(3) extra inputs, $(4) extra link flags
##
## Windows is given no folders because it has no install prefix, it reads what it needs from beside
## the executable.

FRONTEND_DEFINES        := -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"
FRONTEND_FOLDERS        := -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

FRONTEND_DEFINES_NATIVE := $(FRONTEND_DEFINES) $(FRONTEND_FOLDERS)
FRONTEND_DEFINES_LINUX  := $(FRONTEND_DEFINES) $(FRONTEND_FOLDERS)
FRONTEND_DEFINES_WIN    := $(FRONTEND_DEFINES)

frontend_link = $(CC_$(1)) $(CCFLAGS) $(CFLAGS_$(1)) $(HARDEN_FRONTEND_$(1)) $(DEPFLAGS) -MF $(2) src/main.c $(CORE_$(1)) $(3) -o $@ $(LFLAGS_$(1)) $(if $(filter $(1),$(SHARED_PLATFORMS)),$(LFLAGS_FRONTEND_$(1))) $(4) $(FRONTEND_DEFINES_$(1))

$(HASHCAT_FRONTEND): src/main.c $(CORE_NATIVE) obj/arrangement
	$(call frontend_link,NATIVE,obj/main.NATIVE.d,,)

##
## Rules: the plugins
##
## A module, a bridge and a feed are the same artifact. One C source, sometimes a few more, linked
## into a shared object the frontend loads at runtime, against the core of its own platform. What
## differs between the three kinds is the directory, the interface version macro, and whether a
## single plugin brings sources or flags of its own. So one command builds all of them, written once
## instead of once per kind and platform.
##
## The inputs are named rather than taken from $^. The generated dependency files add headers to the
## prerequisite list, and a header on a compiler command line is an input file, not a dependency.
##
## $(1) platform, $(2) inputs, $(3) dependency file or empty, $(4) interface macro, $(5) the NAME of
## a variable holding the flags of this one plugin. A name and not the flags themselves, because
## $(call) cuts its arguments at every comma and a flag is allowed to contain one. Those flags come
## last, so a plugin cannot put its own include path in front of the tree's.

plugin_link = $(CC_$(1)) $(CCFLAGS) $(CFLAGS_PLUGIN_$(1)) $(CFLAGS_ABI) $(if $(3),$(DEPFLAGS) -MF $(3)) $(2) $(CORE_$(1)) -o $@ $(LFLAGS_$(1)) $(if $(filter $(1),$(SHARED_PLATFORMS)),$(LFLAGS_PLUGIN_$(1))) -shared -fPIC -D $(4) $($(5))

define PLUGIN_RULES

modules/module_%.$(PLUGIN_SUFFIX_$(1)): src/modules/module_%.c $$(CORE_$(1)) obj/arrangement
	$$(call plugin_link,$(1),$$<,obj/module_$$*.$(1).d,MODULE_INTERFACE_VERSION_CURRENT=$$(MODULE_INTERFACE_VERSION),)

feeds/feed_%.$(PLUGIN_SUFFIX_$(1)): src/feeds/feed_%.c $$(CORE_$(1)) obj/arrangement
	$$(call plugin_link,$(1),$$<,obj/feed_$$*.$(1).d,FEEDS_INTERFACE_VERSION_CURRENT=$$(FEEDS_INTERFACE_VERSION),)

bridges/bridge_%.$(PLUGIN_SUFFIX_$(1)): src/bridges/bridge_%.c $$(CORE_$(1)) obj/arrangement
	$$(call plugin_link,$(1),$$<,,BRIDGE_INTERFACE_VERSION_CURRENT=$$(BRIDGE_INTERFACE_VERSION),)

MODULES_LIB_$(1)        := $$(patsubst src/modules/module_%.c,modules/module_%.$(PLUGIN_SUFFIX_$(1)),$$(MODULES_SRC))
BRIDGES_LIB_$(1)        := $$(patsubst src/bridges/bridge_%.c,bridges/bridge_%.$(PLUGIN_SUFFIX_$(1)),$$(BRIDGES_SRC))
FEEDS_LIB_$(1)          := $$(patsubst src/feeds/feed_%.c,feeds/feed_%.$(PLUGIN_SUFFIX_$(1)),$$(FEEDS_SRC))

.PHONY: modules$(PHONY_SUFFIX_$(1)) bridges$(PHONY_SUFFIX_$(1)) feeds$(PHONY_SUFFIX_$(1))

modules$(PHONY_SUFFIX_$(1)): $$(MODULES_LIB_$(1))
bridges$(PHONY_SUFFIX_$(1)): $$(BRIDGES_LIB_$(1))
feeds$(PHONY_SUFFIX_$(1)):   $$(FEEDS_LIB_$(1))

endef

$(foreach P,$(PLUGIN_PLATFORMS),$(eval $(call PLUGIN_RULES,$(P))))

## A bridge that asked for more than its own source gets a rule of its own, from the same command.
## $(1) platform, $(2) bridge

define BRIDGE_RULES

BRIDGE_FLAGS_$(2)_$(1)  := $(BRIDGE_CFLAGS_$(2)) $(BRIDGE_CFLAGS_$(2)_$(1))

bridges/$(2).$(PLUGIN_SUFFIX_$(1)): $$(BRIDGE_SRC_$(2)) $$(CORE_$(1)) obj/arrangement $(BRIDGE_DEPS_$(2)_$(1))
	$$(call plugin_link,$(1),$$(BRIDGE_SRC_$(2)),,BRIDGE_INTERFACE_VERSION_CURRENT=$$(BRIDGE_INTERFACE_VERSION),BRIDGE_FLAGS_$(2)_$(1))

endef

$(foreach P,$(PLUGIN_PLATFORMS),$(foreach B,$(BRIDGES_ALL), \
  $(if $(BRIDGE_SKIP_$(B)_$(P)),,$(eval $(call BRIDGE_RULES,$(P),$(B))))))

##
## Targets: native compilation
##

.PHONY: default
default: $(HASHCAT_FRONTEND) modules bridges feeds

.PHONY: clean
clean:
	$(RM) -f $(HASHCAT_FRONTEND)
	$(RM) -f $(HASHCAT_LIBRARY)
	$(RM) -f libhashcat.so.*
	$(RM) -f hashcat.dll
	$(RM) -rf modules/*.dSYM
	$(RM) -rf bridges/*.dSYM
	$(RM) -rf feeds/*.dSYM
	$(RM) -rf *.dSYM
	$(RM) -f bridges/subs/*.dll
	$(RM) -f bridges/subs/*.so
	$(RM) -f bridges/subs/*.su
	$(RM) -f bridges/*.dll
	$(RM) -f bridges/*.so
	$(RM) -f bridges/*.su
	$(RM) -f feeds/*.dll
	$(RM) -f feeds/*.so
	$(RM) -f feeds/*.su
	$(RM) -f modules/*.dll
	$(RM) -f modules/*.so
	$(RM) -f modules/*.su
	$(RM) -f obj/*/*/*.o
	$(RM) -f obj/*/*/*.su
	$(RM) -f obj/*/*/*.d
	$(RM) -f obj/*/*.o
	$(RM) -f obj/*/*.su
	$(RM) -f obj/*/*.d
	$(RM) -f obj/*.o
	$(RM) -f obj/*.su
	$(RM) -f obj/*.d
	$(RM) -f obj/*.a
	$(RM) -f obj/*.c
	$(RM) -f obj/arrangement
	$(RM) -f *.dylib
	$(RM) -f *.bin *.exe
	$(RM) -f *.pid
	$(RM) -f *.log
	$(RM) -f *.su
	$(RM) -f core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf kernels
	$(RM) -rf Rust/bridges/*/target
	$(RM) -rf Rust/feeds/*/target
	$(RM) -rf Rust/hashcat-sys/src/bindings.rs

.PHONY: distclean
distclean: clean
	$(RM) -f *.restore
	$(RM) -f *.potfile
	$(RM) -f *.out
	$(RM) -f brain.*
	$(RM) -rf test_[0-9]*
	$(RM) -rf tools/luks_tests
	$(RM) -rf tools/luks2_tests

##
## Targets: cross compilation (binary release version)
##

ifneq (,$(filter LINUX,$(PLATFORMS)))

ifeq ($(UNAME),Darwin)
.PHONY: binaries
binaries: win

.PHONY: host_win
host_win:   hashcat.exe

.PHONY: win
win:   host_win   modules_win   bridges_win   feeds_win
else
.PHONY: binaries
binaries: linux win

.PHONY: host_linux host_win
host_linux: hashcat.bin
host_win:   hashcat.exe

.PHONY: linux win
linux: host_linux modules_linux bridges_linux feeds_linux
win:   host_win   modules_win   bridges_win   feeds_win
endif

hashcat.bin: src/main.c $(CORE_LINUX) obj/arrangement
	$(call frontend_link,LINUX,obj/main.LINUX.d,,)

# the frontend keeps iconv on its own link line for the arrangement where there is no library to
# carry it, and links nothing extra out of it when there is

hashcat.exe: src/main.c $(CORE_WIN) $(WIN_ICONV)/lib/libiconv.a obj/arrangement
	$(call frontend_link,WIN,obj/main.WIN.d,$(WIN_ICONV)/lib/libiconv.a,)

endif

##
## Targets: Linux install
##

# allow (whitelist) "make install" only on unix-based systems (also disallow cygwin/msys)

ifneq ($(findstring install,$(MAKECMDGOALS)),)
  ifeq (,$(filter $(UNAME),Linux FreeBSD OpenBSD NetBSD DragonFly Darwin))
    define ERROR_INSTALL_DISALLOWED
! The 'install' target is not allowed on this operating system ($(UNAME)). \
Only Linux, FreeBSD, OpenBSD, NetBSD, DragonFly and Darwin can use the 'install' target
    endef

    $(error $(ERROR_INSTALL_DISALLOWED))
  endif
endif

.PHONY: install
ifeq ($(SHARED),1)
install: install_docs install_shared install_tools install_library install_library_dev install_tunings install_kernels install_modules install_bridges install_feeds install_hashcat
else
install: install_docs install_shared install_tools                                     install_tunings install_kernels install_modules install_bridges install_feeds install_hashcat
endif

# we need this extra target to make sure that for parallel builds (i.e. 2+ Makefile targets could possible run at the same time)
# the root folder of the shared directory is created first (and is a dependency for the targets that depend on it)

.PHONY: install_make_library_dev_root
install_make_library_dev_root:
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_DEV_ROOT_FOLDER)

.PHONY: install_make_shared_root
install_make_shared_root:
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_ROOT_FOLDER)

.PHONY: install_docs
install_docs: install_make_shared_root
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/charsets
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/docs
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/layouts
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/masks
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/rules
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/extra
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion
	$(INSTALL) -m 644 example.dict                                          $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example0.hash                                         $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example400.hash                                       $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example500.hash                                       $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 example0.sh                                           $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 example400.sh                                         $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 example500.sh                                         $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 extra/tab_completion/hashcat.sh                       $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/
	$(INSTALL) -m 644 extra/tab_completion/howto.txt                        $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/
	$(INSTALL) -m 755 extra/tab_completion/install                          $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/
	$(FIND) charsets/ -type d -exec $(INSTALL) -m 755 -d                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) charsets/ -type f -exec $(INSTALL) -m 644 {}                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) docs/     -type d -exec $(INSTALL) -m 755 -d                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) docs/     -type f -exec $(INSTALL) -m 644 {}                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) layouts/  -type d -exec $(INSTALL) -m 755 -d                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) layouts/  -type f -exec $(INSTALL) -m 644 {}                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) masks/    -type d -exec $(INSTALL) -m 755 -d                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) masks/    -type f -exec $(INSTALL) -m 644 {}                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) rules/    -type d -exec $(INSTALL) -m 755 -d                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) rules/    -type f -exec $(INSTALL) -m 644 {}                    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(SED) $(SED_IN_PLACE) 's/\.\/hashcat/hashcat/'                         $(DESTDIR)$(DOCUMENT_FOLDER)/example0.sh
	$(SED) $(SED_IN_PLACE) 's/\.\/hashcat/hashcat/'                         $(DESTDIR)$(DOCUMENT_FOLDER)/example400.sh
	$(SED) $(SED_IN_PLACE) 's/\.\/hashcat/hashcat/'                         $(DESTDIR)$(DOCUMENT_FOLDER)/example500.sh

.PHONY: install_shared
install_shared: install_make_shared_root
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)
	$(INSTALL) -m 644 hashcat.hcstat2                                       $(DESTDIR)$(SHARED_FOLDER)/

.PHONY: install_tunings
install_tunings: install_shared
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/tunings
	$(FIND) tunings/  -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/tunings/{} \;
	$(FIND) tunings/  -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/tunings/{} \;

.PHONY: install_kernels
install_kernels: install_shared
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/OpenCL
	$(FIND) OpenCL/   -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/OpenCL/{} \;
	$(FIND) OpenCL/   -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/OpenCL/{} \;

.PHONY: install_modules
install_modules: install_shared modules
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/modules
	$(FIND) modules/  -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/modules/{} \;
	$(FIND) modules/  -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/modules/{} \;

.PHONY: install_bridges
install_bridges: install_shared bridges
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/bridges
	$(FIND) bridges/  -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/bridges/{} \;
	$(FIND) bridges/  -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/bridges/{} \;

.PHONY: install_feeds
install_feeds: install_shared feeds
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/feeds
	$(FIND) feeds/    -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/feeds/{} \;
	$(FIND) feeds/    -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/feeds/{} \;

.PHONY: install_library
install_library: $(HASHCAT_LIBRARY)
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_FOLDER)
	$(INSTALL) -m 755 $(HASHCAT_LIBRARY)                                    $(DESTDIR)$(LIBRARY_FOLDER)/

.PHONY: install_library_dev
install_library_dev: install_make_library_dev_root obj/api.c
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_DEV_FOLDER)
	$(if $(HASHCAT_LIBRARY_DEV_$(FORMAT_NATIVE)),ln -sf $(HASHCAT_LIBRARY_NATIVE) $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY_DEV_$(FORMAT_NATIVE)))
	$(INSTALL) -m 644 $(API_HEADERS)                                        $(DESTDIR)$(LIBRARY_DEV_FOLDER)/
	@for HEADER in $(API_DEP_HEADERS); do \
	  RELATIVE="$$HEADER"; \
	  for ROOT in $(API_DEP_ROOTS); do \
	    case "$$HEADER" in "$$ROOT"/*) RELATIVE="$${HEADER#$$ROOT/}"; break ;; esac; \
	  done; \
	  echo "$(INSTALL) -m 644 $$HEADER $(DESTDIR)$(LIBRARY_DEV_FOLDER)/$$RELATIVE"; \
	  $(INSTALL) -m 755 -d "$(DESTDIR)$(LIBRARY_DEV_FOLDER)/$$(dirname "$$RELATIVE")"; \
	  $(INSTALL) -m 644 "$$HEADER" "$(DESTDIR)$(LIBRARY_DEV_FOLDER)/$$RELATIVE"; \
	done

.PHONY: install_hashcat
install_hashcat: $(HASHCAT_FRONTEND)
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(INSTALL_FOLDER)
	$(INSTALL) -m 755 $(HASHCAT_FRONTEND)                                   $(DESTDIR)$(INSTALL_FOLDER)/

.PHONY: install_tools
install_tools:
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(INSTALL_FOLDER)
	$(INSTALL) -m 755 ${TOOLS}                                              $(DESTDIR)$(INSTALL_FOLDER)/

.PHONY: uninstall
uninstall:
	$(RM) -f  $(DESTDIR)$(INSTALL_FOLDER)/$(HASHCAT_FRONTEND)
	$(RM) -f  $(addprefix $(DESTDIR)$(INSTALL_FOLDER)/,$(notdir ${TOOLS}))
	$(RM) -f  $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY)
	$(RM) -rf $(DESTDIR)$(LIBRARY_DEV_FOLDER)
	$(RM) -rf $(DESTDIR)$(SHARED_FOLDER)
	$(RM) -rf $(DESTDIR)$(DOCUMENT_FOLDER)
