##
## Author......: See docs/credits.txt
## License.....: MIT
##

SHARED                  ?= 0
DEBUG                   := 0
PRODUCTION              := 1
PRODUCTION_VERSION      := v6.2.6
ENABLE_CUBIN            ?= 1
ENABLE_BRAIN            ?= 1
ENABLE_UNRAR            ?= 1
USE_SYSTEM_LZMA         ?= 0
USE_SYSTEM_ZLIB         ?= 0
USE_SYSTEM_OPENCL       ?= 0
USE_SYSTEM_XXHASH       ?= 0
## do not change, requires some hacks
USE_SYSTEM_UNRAR        ?= 0

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

ifeq (,$(filter $(UNAME),Linux FreeBSD NetBSD Darwin CYGWIN MSYS2))
$(error "! Your Operating System ($(UNAME)) is not supported by this Makefile")
endif

ifeq ($(DEBUG),1)
$(info "## Detected Operating System : $(UNAME)")
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

ifeq ($(UNAME),Darwin)
CC                      := clang
CXX                     := clang++
# the sed -i option of macOS requires a parameter for the backup file (we just use "")
AR                      := /usr/bin/ar
SED                     := /usr/bin/sed
SED_IN_PLACE            := -i ""
DARWIN_VERSION          := $(shell uname -r | cut -d. -f1)
IS_APPLE_SILICON        := $(shell lipo /bin/zsh -verify_arch arm64e && echo 1 || echo 0)
endif

ifneq (,$(filter $(UNAME),FreeBSD NetBSD))
CC                      := cc
CXX                     := c++
SED                     := gsed
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

LFLAGS                  := $(LDFLAGS)

ifeq ($(PRODUCTION),0)
CFLAGS                  += -W
CFLAGS                  += -Wall
CFLAGS                  += -Wextra
endif

## because LZMA SDK
ifeq ($(CC),clang)
CFLAGS                  += -Wno-enum-conversion
CFLAGS                  += -Wno-typedef-redefinition
endif

ifeq ($(USE_SYSTEM_LZMA),0)
CFLAGS_LZMA             += -D_7ZIP_ST
ifneq ($(CC),clang)
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
endif

## because UNRAR
ifeq ($(ENABLE_UNRAR),1)
ifeq ($(USE_SYSTEM_UNRAR),0)
ifneq ($(CC),clang)
CFLAGS_UNRAR            += -Wno-class-memaccess
CFLAGS_UNRAR            += -Wno-misleading-indentation
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
CFLAGS_UNRAR            += -Wno-format-overflow
endif
endif

ifeq ($(DEBUG),0)
CFLAGS                  += -O2
ifneq ($(UNAME),Darwin)
LFLAGS                  += -s
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

# brain and xxHash
ifeq ($(ENABLE_BRAIN),1)
CFLAGS                  += -DWITH_BRAIN
CFLAGS                  += -I$(DEPS_XXHASH_PATH)
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
LFLAGS                  += -lstdc++
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

ifeq ($(UNAME),FreeBSD)
ifndef PORTNAME
CFLAGS_NATIVE           := $(CFLAGS)
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -lm
LFLAGS_NATIVE           += -liconv
endif
endif # FreeBSD

ifeq ($(UNAME),NetBSD)
CFLAGS_NATIVE           := $(CFLAGS)
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpthread
endif # NetBSD

ifeq ($(UNAME),Darwin)
export MACOSX_DEPLOYMENT_TARGET=10.15
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
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -liconv

ifeq ($(IS_APPLE_SILICON),1)
CFLAGS_NATIVE           += -arch arm64
CFLAGS_NATIVE           += -arch x86_64
ifeq ($(SHARED),1)
LFLAGS_NATIVE           += -arch arm64
LFLAGS_NATIVE           += -arch x86_64
endif
endif

endif # Darwin

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
EMU_OBJS_ALL            += emu_inc_rp emu_inc_rp_optimized
EMU_OBJS_ALL            += emu_inc_hash_md4 emu_inc_hash_md5 emu_inc_hash_ripemd160 emu_inc_hash_sha1 emu_inc_hash_sha256 emu_inc_hash_sha384 emu_inc_hash_sha512 emu_inc_hash_streebog256 emu_inc_hash_streebog512 emu_inc_ecc_secp256k1 emu_inc_bignum_operations
EMU_OBJS_ALL            += emu_inc_cipher_aes emu_inc_cipher_camellia emu_inc_cipher_des emu_inc_cipher_kuznyechik emu_inc_cipher_serpent emu_inc_cipher_twofish
EMU_OBJS_ALL            += emu_inc_hash_base58

OBJS_ALL                := affinity autotune backend benchmark bitmap bitops combinator common convert cpt cpu_crc32 debugfile dictstat dispatch dynloader event ext_ADL ext_cuda ext_hip ext_nvapi ext_nvml ext_nvrtc ext_hiprtc ext_OpenCL ext_sysfs_amdgpu ext_sysfs_cpu ext_iokit ext_lzma filehandling folder hashcat hashes hlfmt hwmon induct interface keyboard_layout locking logfile loopback memory monitor mpsp outfile_check outfile pidfile potfile restore rp rp_cpu selftest slow_candidates shared status stdout straight terminal thread timer tuningdb usage user_options wordlist $(EMU_OBJS_ALL)

ifeq ($(UNAME),Darwin)
OBJS_ALL                += ext_metal
endif

ifeq ($(ENABLE_BRAIN),1)
OBJS_ALL                += brain
endif

NATIVE_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.o)
LINUX_OBJS              := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.o)
WIN_OBJS                := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.o)

ifeq ($(USE_SYSTEM_LZMA),0)
OBJS_LZMA               := 7zCrc 7zCrcOpt 7zFile 7zStream Alloc Bra Bra86 BraIA64 CpuArch Delta LzmaDec Lzma2Dec Sha256 Sha256Opt Xz XzCrc64 XzCrc64Opt XzDec XzIn

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
## Targets: Native Compilation
##

.PHONY: default
default: $(HASHCAT_FRONTEND) modules

.PHONY: clean
clean:
	$(RM) -f $(HASHCAT_FRONTEND)
	$(RM) -f $(HASHCAT_LIBRARY)
	$(RM) -rf modules/*.dSYM
	$(RM) -f modules/*.dll
	$(RM) -f modules/*.so
	$(RM) -f obj/*/*/*.o
	$(RM) -f obj/*/*.o
	$(RM) -f obj/*.o
	$(RM) -f obj/*.a
	$(RM) -rf *.dSYM
	$(RM) -f *.dylib
	$(RM) -f *.bin *.exe
	$(RM) -f *.pid
	$(RM) -f *.log
	$(RM) -f core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf kernels

.PHONY: distclean
distclean: clean
	$(RM) -f *.restore
	$(RM) -f *.potfile
	$(RM) -f *.out
	$(RM) -f hashcat.dictstat2
	$(RM) -f brain.*
	$(RM) -rf test_[0-9]*
	$(RM) -rf tools/luks_tests

##
## Targets: Linux install
##

# allow (whitelist) "make install" only on unix-based systems (also disallow cygwin/msys)

ifneq ($(findstring install,$(MAKECMDGOALS)),)
  ifeq (,$(filter $(UNAME),Linux FreeBSD Darwin NetBSD))
    define ERROR_INSTALL_DISALLOWED
! The 'install' target is not allowed on this operating system ($(UNAME)). \
Only Linux, FreeBSD, NetBSD and Darwin can use the 'install' target
    endef

    $(error $(ERROR_INSTALL_DISALLOWED))
  endif
endif

.PHONY: install
ifeq ($(SHARED),1)
install: install_docs install_shared install_library install_library_dev install_tunings install_kernels install_modules install_hashcat
else
install: install_docs install_shared                                     install_tunings install_kernels install_modules install_hashcat
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
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(DOCUMENT_FOLDER)/tools
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
	$(FIND) tools/    -type f -name '*cat.p[ly]' -exec $(INSTALL) -m 755 {} $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
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

.PHONY: uninstall
uninstall:
	$(RM) -f  $(DESTDIR)$(INSTALL_FOLDER)/$(HASHCAT_FRONTEND)
	$(RM) -f  $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY)
	$(RM) -rf $(DESTDIR)$(LIBRARY_DEV_FOLDER)
	$(RM) -rf $(DESTDIR)$(SHARED_FOLDER)
	$(RM) -rf $(DESTDIR)$(DOCUMENT_FOLDER)

##
## native compiled hashcat library and frontend
##

obj/%.NATIVE.o: src/%.c
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $< -o $@ -fpic

obj/%.NATIVE.o: src/%.m
	$(CC) -c $(CCFLAGS) $(CFLAGS_NATIVE) $< -o $@ -fpic

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
	$(AR) rcs $@ $^

ifeq ($(UNAME),Darwin)
$(HASHCAT_LIBRARY): $(NATIVE_OBJS)
	$(CC)                     $^ -o $@                    $(LFLAGS_NATIVE) -shared -install_name $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY) -current_version $(VERSION_PURE) -compatibility_version $(VERSION_PURE)
else
$(HASHCAT_LIBRARY): $(NATIVE_OBJS)
	$(CC)                     $^ -o $@                    $(LFLAGS_NATIVE) -shared -Wl,-soname,$(HASHCAT_LIBRARY)
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
## Cross Compilation (binary release version)
##

ifeq ($(UNAME),Linux)

##
## Compiler paths
##

CC_LINUX                := gcc
CXX_LINUX               := g++
CC_WIN                  := x86_64-w64-mingw32-gcc
CXX_WIN                 := x86_64-w64-mingw32-g++

AR_LINUX                := ar
AR_WIN                  := x86_64-w64-mingw32-ar

## To compile win-iconv with mingw clone from here: https://github.com/win-iconv/win-iconv
##
## Then patch the makefile with the patches from tools/win-iconv-64.diff and run make install
##

WIN_ICONV               := /opt/win-iconv-64

##
## Compiler options
##

CFLAGS_CROSS_LINUX      := $(CFLAGS)
CFLAGS_CROSS_LINUX      += -fPIC
CFLAGS_CROSS_LINUX      += -DWITH_HWMON
CFLAGS_CROSS_WIN        := $(CFLAGS)
CFLAGS_CROSS_WIN        += -fPIC
CFLAGS_CROSS_WIN        += -I$(WIN_ICONV)/include/
CFLAGS_CROSS_WIN        += -DWITH_HWMON
CFLAGS_CROSS_WIN        += -D__USE_MINGW_ANSI_STDIO=0

LFLAGS_CROSS_LINUX      := $(LFLAGS)
LFLAGS_CROSS_LINUX      += -lpthread
LFLAGS_CROSS_LINUX      += -ldl
LFLAGS_CROSS_LINUX      += -lm
LFLAGS_CROSS_WIN        := $(LFLAGS)
LFLAGS_CROSS_WIN        += -Wl,--dynamicbase
LFLAGS_CROSS_WIN        += -Wl,--nxcompat
LFLAGS_CROSS_WIN        += -lpsapi
LFLAGS_CROSS_WIN        += -lws2_32
LFLAGS_CROSS_WIN        += -lpowrprof
LFLAGS_CROSS_WIN        += -static -static-libgcc -static-libstdc++

##
## Targets
##

.PHONY: binaries
binaries: linux win

.PHONY: host_linux host_win
host_linux: hashcat.bin
host_win:   hashcat.exe

.PHONY: linux win
linux: host_linux modules_linux
win:   host_win   modules_win

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
## cross compiled hashcat
##

obj/%.LINUX.o: src/%.c
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX) -c -o $@ $<

obj/%.WIN.o:   src/%.c
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)   -c -o $@ $<

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.LZMA.LINUX.o: $(DEPS_LZMA_PATH)/%.c
	$(CC_LINUX) $(CCFLAGS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_LZMA) -c -o $@ $<

obj/%.LZMA.WIN.o:   $(DEPS_LZMA_PATH)/%.c
	$(CC_WIN)   $(CCFLAGS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_LZMA) -c -o $@ $<
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
	$(CXX_LINUX) $(CXXFLAGS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_UNRAR) -c -o $@ $<

obj/%.UNRAR.WIN.o:   $(DEPS_UNRAR_PATH)/%.cpp
	$(CXX_WIN)   $(CXXFLAGS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_UNRAR) -c -o $@ $<
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

# Give plugin developers a chance to add some 3rd party libraries
include	$(wildcard src/modules/module_*.mk)
