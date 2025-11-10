##
## Author......: See docs/credits.txt
## License.....: MIT
##

SHARED                  ?= 0
DEBUG                   := 0
PRODUCTION              := 0
PRODUCTION_VERSION      := v7.1.2
MACOS_UNIVERSAL_BINARY  ?= 0
ENABLE_LTO              ?= 1
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

# we need to strip the windows version number to be able to build hashcat on cygwin hosts
UNAME                   := $(patsubst CYGWIN_NT-%,CYGWIN,$(UNAME))

# same for msys
UNAME                   := $(patsubst MSYS_NT-%,MSYS2,$(UNAME))
UNAME                   := $(patsubst MINGW32_NT-%,MSYS2,$(UNAME))
UNAME                   := $(patsubst MINGW64_NT-%,MSYS2,$(UNAME))

ifeq (,$(filter $(UNAME),Linux OpenBSD FreeBSD NetBSD DragonFly Darwin CYGWIN MSYS2))
$(error "! Your Operating System ($(UNAME)) is not supported by this Makefile")
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

BUILD_MODE := native

ifneq ($(filter binaries linux host_linux modules_linux bridges_linux feeds_linux win host_win modules_win bridges_win feeds_win,$(MAKECMDGOALS)),)
BUILD_MODE := cross
endif

# force disable LTO if we are in native build and CC == clang and OS is MSYS2 or NetBSD or DragonFly
ifeq ($(BUILD_MODE),native)
ifeq ($(CC),clang)
ifneq (,$(filter MSYS2 NetBSD DragonFly,$(UNAME)))
override ENABLE_LTO := 0
endif
endif
endif

ifeq ($(DEBUG),1)
$(info "## Detected Operating System : $(UNAME)")
$(info "## Detected Build Mode : $(BUILD_MODE)")
$(info "## Detected CC : $(CC)")
$(info "## Detected CXX : $(CXX)")
endif

##
## Makefile flags
##

MAKEFLAGS               += -l -j 8 -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS               += -j 1
endif

##
## Do not modify
##

MODULE_INTERFACE_VERSION := 700
BRIDGE_INTERFACE_VERSION := 700
FEEDS_INTERFACE_VERSION  := 713

##
## Native compiler paths
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

##
## Version
##

ifeq ($(PRODUCTION),1)
VERSION_TAG             := $(PRODUCTION_VERSION)
else
VERSION_TAG             := $(shell git describe --tags --dirty=+ || echo $(PRODUCTION_VERSION))
endif # PRODUCTION

VERSION_PURE            := $(shell echo "$(VERSION_TAG)" | $(SED) 's/.*v\([\.0-9]*\).*/\1/')

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

HASHCAT_FRONTEND        := hashcat
HASHCAT_LIBRARY         := libhashcat.so.$(VERSION_PURE)

ifeq ($(UNAME),Darwin)
HASHCAT_LIBRARY         := libhashcat.$(VERSION_PURE).dylib
endif # Darwin

ifeq ($(UNAME),CYGWIN)
HASHCAT_FRONTEND        := hashcat.exe
HASHCAT_LIBRARY         := hashcat.dll
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
HASHCAT_FRONTEND        := hashcat.exe
HASHCAT_LIBRARY         := hashcat.dll
endif # MSYS2

##
## Misc stuff
##

COMPTIME                := $(shell date +%s)

##
## General compiler and linker options
##

CC_NATIVE_CLANG         := 0

ifneq (,$(findstring clang, $(CC)))
CC_NATIVE_CLANG         := 1
endif

# force disable LTO if MSYS2 and CC is clang
ifeq ($(UNAME),MSYS2)
ifeq ($(CC_NATIVE_CLANG),1)
override ENABLE_LTO     := 0
endif
endif

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

ifeq ($(BUILD_MODE),native)
ifneq ($(UNAME),Darwin)
ifeq ($(USE_MOLD),1)
LFLAGS                  += -fuse-ld=mold
endif
endif
endif

ifeq ($(MAINTAINER_MODE),0)
ifeq ($(BUILD_MODE),native)
ifneq ($(UNAME),Darwin)
ifeq ($(IS_PPC),1)
CFLAGS                  += -mcpu=native
CFLAGS                  += -mtune=native
else
CFLAGS                  += -march=native
CFLAGS                  += -mtune=native
endif
else
ifeq ($(MACOS_UNIVERSAL_BINARY),0)
CFLAGS                  += -march=native
CFLAGS                  += -mtune=native
endif
endif
endif
endif

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

ifeq ($(UNAME),Linux)
IS_RPI                  := $(shell grep -q Raspberry /proc/cpuinfo && echo 1 || echo 0)

ifeq ($(IS_RPI),1)
CFLAGS                  += -mcpu=cortex-a72
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

# xxHash
CFLAGS                  += -I$(DEPS_XXHASH_PATH)
ifeq ($(USE_SYSTEM_XXHASH),1)
LFLAGS                  += -lxxhash
endif

# CUDA binary cache
ifeq ($(ENABLE_CUBIN),1)
CFLAGS                  += -DWITH_CUBIN
endif

# unrar
ifeq ($(ENABLE_UNRAR),1)
CFLAGS                  += -I$(DEPS_UNRAR_PATH)
ifeq ($(UNAME),OpenBSD)
LFLAGS                  += -lc++
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

##
## Native compilation target
##

ifeq ($(UNAME),Linux)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -ldl
LFLAGS_NATIVE           += -lrt
LFLAGS_NATIVE           += -lm
endif # Linux

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
LFLAGS_NATIVE           += -Wl,--dynamicbase
LFLAGS_NATIVE           += -Wl,--nxcompat
LFLAGS_NATIVE           += -lpsapi
LFLAGS_NATIVE           += -liconv
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -Wl,--dynamicbase
LFLAGS_NATIVE           += -Wl,--nxcompat
LFLAGS_NATIVE           += -lpsapi
LFLAGS_NATIVE           += -liconv
LFLAGS_NATIVE           += -lws2_32
LFLAGS_NATIVE           += -lpowrprof
endif # MSYS2

# CCFLAGS only for C compiler
CCFLAGS                 := -std=gnu99

# CXXFLAGS only for C++ compiler
CXXFLAGS                :=

##
## Objects
##

EMU_OBJS_ALL            := emu_general emu_inc_common emu_inc_platform emu_inc_scalar emu_inc_simd
EMU_OBJS_ALL            += emu_inc_rp_common emu_inc_rp emu_inc_rp_optimized
EMU_OBJS_ALL            += emu_inc_hash_md4 emu_inc_hash_md5 emu_inc_hash_ripemd160 emu_inc_hash_sha1 emu_inc_hash_sha256 emu_inc_hash_sha384 emu_inc_hash_sha512 emu_inc_hash_streebog256 emu_inc_hash_streebog512 emu_inc_ecc_secp256k1 emu_inc_bignum_operations
EMU_OBJS_ALL            += emu_inc_cipher_aes emu_inc_cipher_camellia emu_inc_cipher_des emu_inc_cipher_kuznyechik emu_inc_cipher_serpent emu_inc_cipher_twofish
EMU_OBJS_ALL            += emu_inc_hash_base58

OBJS_ALL                := affinity autotune backend benchmark bitmap bitops bridges combinator common convert cpt cpu_crc32 cpu_features debugfile dictstat dispatch dynloader event ext_ADL ext_cuda ext_hip ext_nvapi ext_nvml ext_nvrtc ext_hiprtc ext_OpenCL ext_sysfs_amdgpu ext_sysfs_intelgpu ext_sysfs_cpu ext_lzma filehandling folder hashcat hashes hlfmt hwmon induct interface keyboard_layout locking logfile loopback memory monitor mpsp outfile_check outfile pidfile potfile restore rp rp_cpu selftest slow_candidates shared status stdout straight generic terminal thread timer tuningdb usage user_options wordlist $(EMU_OBJS_ALL)

ifeq ($(ENABLE_BRAIN),1)
OBJS_ALL                += brain
endif

NATIVE_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.o)
LINUX_OBJS              := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.o)
WIN_OBJS                := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.o)

ifeq ($(UNAME),Darwin)
OBJS_METAL              := ext_metal ext_iokit

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_METAL),obj/$(OBJ).METAL.NATIVE.o)
endif

ifeq ($(USE_SYSTEM_LZMA),0)
OBJS_LZMA               := 7zCrc 7zCrcOpt 7zFile 7zStream Alloc Bra Bra86 BraIA64 CpuArch Delta LzmaDec Lzma2Dec MtDec Sha256 Sha256Opt Threads Xz XzCrc64 XzCrc64Opt XzDec XzIn

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LZMA.NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LZMA.LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LZMA.WIN.o)
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
OBJS_ZLIB               := adler32 crc32 deflate inflate inffast inftrees trees gzread gzwrite gzclose zutil gzlib contrib/minizip/unzip contrib/minizip/ioapi

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).ZLIB.NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).ZLIB.LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).ZLIB.WIN.o)
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
OBJS_XXHASH             := xxhash

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).XXHASH.NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).XXHASH.LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).XXHASH.WIN.o)
endif
endif

ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
OBJS_UNRAR              := strlist strfn pathfn smallfn global file filefn filcreat archive arcread unicode system isnt crypt crc rawread encname resource match timefn rdwrfn consio options errhnd rarvm secpassword rijndael getbits sha1 sha256 blake2s hash extinfo extract volume list find unpack headers threadpool rs16 cmddata ui filestr recvol rs scantree qopen hc_decompress_rar

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_UNRAR),obj/$(OBJ).UNRAR.NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_UNRAR),obj/$(OBJ).UNRAR.LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_UNRAR),obj/$(OBJ).UNRAR.WIN.o)
endif
endif

##
## Tools
##

TOOLS                   += $(wildcard tools/*hashcat.pl)
TOOLS                   += $(wildcard tools/*hashcat.py)

##
## Targets: Native Compilation
##

.PHONY: default
default: $(HASHCAT_FRONTEND) modules bridges feeds

.PHONY: clean
clean:
	$(RM) -f $(HASHCAT_FRONTEND)
	$(RM) -f $(HASHCAT_LIBRARY)
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
	$(RM) -f obj/*/*.o
	$(RM) -f obj/*/*.su
	$(RM) -f obj/*.o
	$(RM) -f obj/*.su
	$(RM) -f obj/*.a
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
	$(RM) -f hashcat.dictstat2
	$(RM) -f brain.*
	$(RM) -rf test_[0-9]*
	$(RM) -rf tools/luks_tests
	$(RM) -rf tools/luks2_tests

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
install_library_dev: install_make_library_dev_root
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_DEV_FOLDER)
	$(FIND) include/  -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(LIBRARY_DEV_FOLDER)/{} \;
	$(FIND) include/  -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(LIBRARY_DEV_FOLDER)/{} \;

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

##
## native compiled hashcat library and frontend
##

obj/%.NATIVE.o: src/%.c
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $< -o $@ -fpic

ifeq ($(UNAME),Darwin)
obj/%.METAL.NATIVE.o: src/%.m
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $< -o $@ -fpic
endif

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.LZMA.NATIVE.o: $(DEPS_LZMA_PATH)/%.c
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $(CFLAGS_LZMA) $< -o $@ -fpic
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
obj/%.ZLIB.NATIVE.o: $(DEPS_ZLIB_PATH)/%.c
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $(CFLAGS_ZLIB) $< -o $@ -fpic
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
obj/%.XXHASH.NATIVE.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $< -o $@ -fpic
endif
endif

ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
obj/%.UNRAR.NATIVE.o: $(DEPS_UNRAR_PATH)/%.cpp
	$(CXX) -c $(CXXFLAGS) $(CFLAGS_NATIVE) $(CFLAGS_UNRAR) $< -o $@ -fpic
endif
endif

obj/combined.NATIVE.a: $(NATIVE_OBJS)
ifeq ($(UNAME),Darwin)
ifeq ($(IS_APPLE_SILICON),1)
	$(RM) -f obj/combined.NATIVE.a
endif
endif
	$(AR) rcs $@ $^

ifeq ($(UNAME),Darwin)
$(HASHCAT_LIBRARY): $(NATIVE_OBJS)
	$(CXX)                    $^ -o $@                    $(LFLAGS_NATIVE) -shared -install_name $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY) -current_version $(VERSION_PURE) -compatibility_version $(VERSION_PURE)
else
$(HASHCAT_LIBRARY): $(NATIVE_OBJS)
	$(CXX)                    $^ -o $@                    $(LFLAGS_NATIVE) -shared -Wl,-soname,$(HASHCAT_LIBRARY)
endif

ifeq ($(SHARED),1)
$(HASHCAT_FRONTEND): src/main.c $(HASHCAT_LIBRARY)
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(HASHCAT_LIBRARY) $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
else
$(HASHCAT_FRONTEND): src/main.c obj/combined.NATIVE.a
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@                    $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
endif

##
## native compiled modules
##

MODULE_SUFFIX := so

ifeq ($(UNAME),CYGWIN)
MODULE_SUFFIX := dll
endif

ifeq ($(UNAME),MSYS2)
MODULE_SUFFIX := dll
endif

MODULES_SRC   := $(wildcard src/modules/*.c)

MODULES_DISABLE ?=

ifeq ($(ENABLE_UNRAR),0)
MODULES_SRC     := $(filter-out src/modules/module_23800.c,$(MODULES_SRC))
MODULES_DISABLE += modules/module_23800.so
MODULES_DISABLE += modules/module_23800.dll
endif

$(MODULES_DISABLE): ;

ifeq ($(SHARED),1)
modules/module_%.$(MODULE_SUFFIX): src/modules/module_%.c $(HASHCAT_LIBRARY)
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)
else
modules/module_%.$(MODULE_SUFFIX): src/modules/module_%.c obj/combined.NATIVE.a
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)
endif

MODULES_LIB   := $(patsubst src/modules/module_%.c, modules/module_%.$(MODULE_SUFFIX), $(MODULES_SRC))

.PHONY: modules
modules: $(MODULES_LIB)

##
## native compiled bridges
##

BRIDGE_SUFFIX := so

ifeq ($(UNAME),CYGWIN)
BRIDGE_SUFFIX := dll
endif

ifeq ($(UNAME),MSYS2)
BRIDGE_SUFFIX := dll
endif

BRIDGES_SRC   := $(wildcard src/bridges/*.c)

## not used so far, see modules above
BRIDGES_DISABLE ?=

$(BRIDGES_DISABLE): ;

ifeq ($(SHARED),1)
bridges/bridge_%.$(BRIDGE_SUFFIX): src/bridges/bridge_%.c $(HASHCAT_LIBRARY)
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
else
bridges/bridge_%.$(BRIDGE_SUFFIX): src/bridges/bridge_%.c obj/combined.NATIVE.a
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)
endif

BRIDGES_LIB   := $(patsubst src/bridges/bridge_%.c, bridges/bridge_%.$(BRIDGE_SUFFIX), $(BRIDGES_SRC))

.PHONY: bridges
bridges: $(BRIDGES_LIB)

##
## native compiled feeds
##

FEEDS_SUFFIX := so

ifeq ($(UNAME),CYGWIN)
FEEDS_SUFFIX := dll
endif

ifeq ($(UNAME),MSYS2)
FEEDS_SUFFIX := dll
endif

FEEDS_SRC := $(wildcard src/feeds/*.c)

## not used so far, see modules above
FEEDS_DISABLE ?=

$(FEEDS_DISABLE): ;

ifeq ($(SHARED),1)
feeds/feed_%.$(FEEDS_SUFFIX): src/feeds/feed_%.c $(HASHCAT_LIBRARY)
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D FEEDS_INTERFACE_VERSION_CURRENT=$(FEEDS_INTERFACE_VERSION)
else
feeds/feed_%.$(FEEDS_SUFFIX): src/feeds/feed_%.c obj/combined.NATIVE.a
	$(CC)    $(CCFLAGS) $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D FEEDS_INTERFACE_VERSION_CURRENT=$(FEEDS_INTERFACE_VERSION)
endif

FEEDS_LIB := $(patsubst src/feeds/feed_%.c, feeds/feed_%.$(FEEDS_SUFFIX), $(FEEDS_SRC))

.PHONY: feeds
feeds: $(FEEDS_LIB)

##
## Cross Compilation (binary release version)
##

ifneq (,$(filter $(UNAME),Linux Darwin))

##
## Compiler paths
##

CC_LINUX                := gcc
CXX_LINUX               := g++
CC_WIN                  := x86_64-w64-mingw32-gcc
CXX_WIN                 := x86_64-w64-mingw32-g++

AR_LINUX                := ar
AR_WIN                  := x86_64-w64-mingw32-ar

# See BUILD_WSL.md to make these
WIN_ICONV               := /opt/win-iconv-64
WIN_PYTHON              := /opt/win-python

##
## Compiler options
##

CC_LINUX_CLANG          := 0
CC_WIN_CLANG            := 0

ifneq (,$(findstring clang, $(CC_LINUX)))
CC_LINUX_CLANG          := 1
endif

ifneq (,$(findstring clang, $(CC_WIN)))
CC_WIN_CLANG            := 1
endif

CFLAGS_CROSS_LINUX      := $(CFLAGS)
CFLAGS_CROSS_LINUX      += -fPIC
CFLAGS_CROSS_LINUX      += -DWITH_HWMON

ifeq ($(CC_LINUX_CLANG),1)
CFLAGS_CROSS_LINUX      += -Wno-typedef-redefinition
CFLAGS_CROSS_LINUX      += -Wno-unknown-warning-option
endif

CFLAGS_CROSS_WIN        := $(CFLAGS)
CFLAGS_CROSS_WIN        += -fPIC
CFLAGS_CROSS_WIN        += -I$(WIN_ICONV)/include/
CFLAGS_CROSS_WIN        += -DWITH_HWMON

ifeq ($(CC_WIN_CLANG),1)
CFLAGS_CROSS_WIN        := $(filter-out -fno-plt,$(CFLAGS_CROSS_WIN))
CFLAGS_CROSS_WIN        += --target=x86_64-w64-mingw32
CFLAGS_CROSS_WIN        += -D_CLANG_DISABLE_CRT_DEPRECATION_WARNINGS
CFLAGS_CROSS_WIN        += -D__INTRINSIC_DEFINED___cpuidex=1
CFLAGS_CROSS_WIN        += -D__INTRINSIC_DEFINED__xgetbv=1
CFLAGS_CROSS_WIN        += -Wno-typedef-redefinition
CFLAGS_CROSS_WIN        += -Wno-ignored-attributes
CFLAGS_CROSS_WIN        += -Wno-unknown-warning-option
endif

LFLAGS_CROSS_LINUX      := $(LFLAGS)
LFLAGS_CROSS_LINUX      += -lpthread
LFLAGS_CROSS_LINUX      += -ldl
LFLAGS_CROSS_LINUX      += -lm
LFLAGS_CROSS_LINUX      += -static-libgcc

ifeq ($(CC_LINUX_CLANG),1)
LFLAGS_CROSS_LINUX      += -stdlib=libc++
else
LFLAGS_CROSS_LINUX      += -static-libstdc++
endif

ifeq ($(USE_MOLD),1)
LFLAGS_CROSS_LINUX      += -fuse-ld=mold
else
ifeq ($(ENABLE_LTO),1)
ifeq ($(CC_LINUX_CLANG),1)
LFLAGS_CROSS_LINUX      += -fuse-ld=lld
else
LFLAGS_CROSS_LINUX      += -fuse-ld=gold
endif
endif
endif

LFLAGS_CROSS_WIN        := $(LFLAGS)
ifneq ($(UNAME),Darwin)
LFLAGS_CROSS_WIN        += -lstdc++
endif

ifeq ($(CC_WIN_CLANG),0)
LFLAGS_CROSS_WIN        += -Wl,--dynamicbase
LFLAGS_CROSS_WIN        += -Wl,--nxcompat
endif
LFLAGS_CROSS_WIN        += -lpsapi
LFLAGS_CROSS_WIN        += -lws2_32
LFLAGS_CROSS_WIN        += -lpowrprof

ifeq ($(CC_WIN_CLANG),0)
LFLAGS_CROSS_WIN        += -static
endif
LFLAGS_CROSS_WIN        += -static-libgcc
ifeq ($(CC_WIN_CLANG),0)
LFLAGS_CROSS_WIN        += -static-libstdc++
endif
LFLAGS_CROSS_WIN        += -lole32 -loleaut32 -lwbemuuid

ifeq ($(ENABLE_LTO),1)
ifeq ($(CC_WIN_CLANG),1)
LFLAGS_CROSS_WIN        += -fuse-ld=lld
LFLAGS_CROSS_WIN        += -Wl,--stack,0x200000
endif
endif

CFLAGS_LZMA_WIN         := $(CFLAGS_LZMA)
CFLAGS_UNRAR_WIN        := $(CFLAGS_UNRAR)

ifeq ($(UNAME),Darwin)
CFLAGS_CROSS_WIN        := $(filter-out -Wno-typedef-redefinition,$(CFLAGS_CROSS_WIN))

CFLAGS_LZMA_WIN         += -Wno-misleading-indentation

CFLAGS_UNRAR_WIN        += -Wno-misleading-indentation
CFLAGS_UNRAR_WIN        += -Wno-class-memaccess
endif

ifeq ($(IS_ARM),1)
CFLAGS_CROSS_LINUX      += -DSSE2NEON_SUPPRESS_WARNINGS
CFLAGS_CROSS_LINUX      += -I$(DEPS_SSE2NEON)
endif

##
## Targets
##

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

##
## cross compiled modules
##

MODULES_LIB_LINUX   := $(patsubst src/modules/module_%.c, modules/module_%.so,  $(MODULES_SRC))
MODULES_LIB_WIN     := $(patsubst src/modules/module_%.c, modules/module_%.dll, $(MODULES_SRC))

.PHONY: modules_linux modules_win
modules_linux: $(MODULES_LIB_LINUX)
modules_win:   $(MODULES_LIB_WIN)

modules/module_%.so:  src/modules/module_%.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)

modules/module_%.dll: src/modules/module_%.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)

##
## cross compiled bridges
##

BRIDGES_LIB_LINUX   := $(patsubst src/bridges/bridge_%.c, bridges/bridge_%.so,  $(BRIDGES_SRC))
BRIDGES_LIB_WIN     := $(patsubst src/bridges/bridge_%.c, bridges/bridge_%.dll, $(BRIDGES_SRC))

.PHONY: bridges_linux bridges_win
bridges_linux: $(BRIDGES_LIB_LINUX)
bridges_win:   $(BRIDGES_LIB_WIN)

bridges/bridge_%.so:  src/bridges/bridge_%.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)

bridges/bridge_%.dll: src/bridges/bridge_%.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D BRIDGE_INTERFACE_VERSION_CURRENT=$(BRIDGE_INTERFACE_VERSION)

##
## cross compiled feeds
##

FEEDS_LIB_LINUX   := $(patsubst src/feeds/feed_%.c, feeds/feed_%.so,  $(FEEDS_SRC))
FEEDS_LIB_WIN     := $(patsubst src/feeds/feed_%.c, feeds/feed_%.dll, $(FEEDS_SRC))

.PHONY: feeds_linux feeds_win
feeds_linux: $(FEEDS_LIB_LINUX)
feeds_win:   $(FEEDS_LIB_WIN)

feeds/feed_%.so:  src/feeds/feed_%.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D FEEDS_INTERFACE_VERSION_CURRENT=$(FEEDS_INTERFACE_VERSION)

feeds/feed_%.dll: src/feeds/feed_%.c obj/combined.WIN.a
	$(CC_WIN)    $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D FEEDS_INTERFACE_VERSION_CURRENT=$(FEEDS_INTERFACE_VERSION)

##
## cross compiled hashcat
##

obj/%.LINUX.o: src/%.c
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX) -c -o $@ $<

obj/%.WIN.o:   src/%.c
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)   -c -o $@ $<

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.LZMA.LINUX.o: $(DEPS_LZMA_PATH)/%.c
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_LZMA)     -c -o $@ $<

obj/%.LZMA.WIN.o:   $(DEPS_LZMA_PATH)/%.c
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_LZMA_WIN) -c -o $@ $<
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
obj/%.ZLIB.LINUX.o: $(DEPS_ZLIB_PATH)/%.c
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_ZLIB) -c -o $@ $<

obj/%.ZLIB.WIN.o:   $(DEPS_ZLIB_PATH)/%.c
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_ZLIB) -c -o $@ $<
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
obj/%.XXHASH.LINUX.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX) -c -o $@ $<

obj/%.XXHASH.WIN.o:   $(DEPS_XXHASH_PATH)/%.c
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)   -c -o $@ $<
endif
endif

ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
obj/%.UNRAR.LINUX.o: $(DEPS_UNRAR_PATH)/%.cpp
	$(CXX_LINUX) $(CXXFLAGS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_UNRAR)     -c -o $@ $<

obj/%.UNRAR.WIN.o:   $(DEPS_UNRAR_PATH)/%.cpp
	$(CXX_WIN)   $(CXXFLAGS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_UNRAR_WIN) -c -o $@ $<
endif
endif

obj/combined.LINUX.a: $(LINUX_OBJS)
	$(AR_LINUX) rcs $@ $^

obj/combined.WIN.a: $(WIN_OBJS)
	$(AR_WIN) rcs $@ $^

hashcat.bin: src/main.c obj/combined.LINUX.a
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat.exe: src/main.c obj/combined.WIN.a $(WIN_ICONV)/lib/libiconv.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)      -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat.dll: src/main.c obj/combined.WIN.a $(WIN_ICONV)/lib/libiconv.a
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)      -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -shared

endif

# Give developers a chance to add some 3rd party dependancies
include	$(wildcard src/modules/*.mk)
include $(wildcard src/bridges/*.mk)
include $(wildcard src/feeds/*.mk)
