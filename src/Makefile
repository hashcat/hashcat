##
## Author......: See docs/credits.txt
## License.....: MIT
##

SHARED                  := 0
DEBUG                   := 0
PRODUCTION              := 0
PRODUCTION_VERSION      := v5.1.0
ENABLE_BRAIN            := 1
USE_SYSTEM_LZMA         := 0
USE_SYSTEM_ZLIB         := 0
USE_SYSTEM_OPENCL       := 0
USE_SYSTEM_XXHASH       := 0

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

ifeq (,$(filter $(UNAME),Linux FreeBSD Darwin CYGWIN MSYS2))
$(error "! Your Operating System ($(UNAME)) is not supported by this Makefile")
endif

ifeq ($(DEBUG),1)
$(warning "## Detected Operating System : $(UNAME)")
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

MODULE_INTERFACE_VERSION := 520

##
## Native compiler paths
##

CC                      := gcc
AR                      := ar
FIND                    := find
INSTALL                 := install
RM                      := rm
SED                     := sed
SED_IN_PLACE            := -i

ifeq ($(UNAME),Darwin)
CC                      := clang
# the sed -i option of macOS requires a parameter for the backup file (we just use "")
AR                      := /usr/bin/ar
SED                     := /usr/bin/sed
SED_IN_PLACE            := -i ""
PROD_VERS               := $(shell sw_vers -productVersion | cut -d. -f2)
endif

ifeq ($(UNAME),FreeBSD)
CC                      := cc
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
## Depencies paths
##

ifeq ($(USE_SYSTEM_LZMA),0)
DEPS_LZMA_PATH          := deps/LZMA-SDK/C
else
DEPS_LZMA_PATH          := $(LIBRARY_DEV_ROOT_FOLDER)/
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
DEPS_ZLIB_PATH          := deps/zlib/
else
DEPS_ZLIB_PATH          := $(LIBRARY_DEV_ROOT_FOLDER)/
endif

ifeq ($(USE_SYSTEM_OPENCL),0)
DEPS_OPENCL_PATH        := deps/OpenCL-Headers
else
DEPS_OPENCL_PATH        := $(LIBRARY_DEV_ROOT_FOLDER)/
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
DEPS_XXHASH_PATH        := deps/xxHash
else
DEPS_XXHASH_PATH        := $(LIBRARY_DEV_ROOT_FOLDER)/
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
endif

## because ZLIB
ifeq ($(USE_SYSTEM_ZLIB),0)
CFLAGS_ZLIB             += -Wno-implicit-fallthrough
CFLAGS_ZLIB             += -Wno-implicit-function-declaration
CFLAGS_ZLIB             += -Wno-unused-parameter
CFLAGS_ZLIB             += -DIOAPI_NO_64
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

CFLAGS                  += -pipe -std=gnu99 -Iinclude/ -IOpenCL/

# LZMA
CFLAGS                  += -I$(DEPS_LZMA_PATH)
ifeq ($(USE_SYSTEM_LZMA),1)
LFLAGS                  += -llzmasdk
endif

# ZLIB
CFLAGS                  += -I$(DEPS_ZLIB_PATH)
ifeq ($(USE_SYSTEM_ZLIB),1)
LFLAGS                  += -lz
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
endif
endif # FreeBSD

ifeq ($(UNAME),Darwin)
export MACOSX_DEPLOYMENT_TARGET=10.9
CFLAGS_NATIVE           := $(CFLAGS)

ifeq ($(shell test $(PROD_VERS) -le 11; echo $$?), 0)
CFLAGS_NATIVE           += -DMISSING_CLOCK_GETTIME
endif

LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -framework OpenCL
LFLAGS_NATIVE           += -lpthread
LFLAGS_NATIVE           += -liconv
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
endif # MSYS2

##
## Objects
##

EMU_OBJS_ALL            := emu_general emu_inc_common emu_inc_platform emu_inc_scalar emu_inc_simd
EMU_OBJS_ALL            += emu_inc_rp emu_inc_rp_optimized
EMU_OBJS_ALL            += emu_inc_truecrypt_crc32 emu_inc_truecrypt_keyfile emu_inc_truecrypt_xts emu_inc_veracrypt_xts
EMU_OBJS_ALL            += emu_inc_hash_md4 emu_inc_hash_md5 emu_inc_hash_ripemd160 emu_inc_hash_sha1 emu_inc_hash_sha256 emu_inc_hash_sha384 emu_inc_hash_sha512 emu_inc_hash_streebog256 emu_inc_hash_streebog512
EMU_OBJS_ALL            += emu_inc_cipher_aes emu_inc_cipher_camellia emu_inc_cipher_des emu_inc_cipher_kuznyechik emu_inc_cipher_serpent emu_inc_cipher_twofish

OBJS_ALL                := affinity autotune backend benchmark bitmap bitops combinator common convert cpt cpu_crc32 debugfile dictstat dispatch dynloader event ext_ADL ext_cuda ext_nvapi ext_nvml ext_nvrtc ext_OpenCL ext_sysfs ext_lzma filehandling folder hashcat hashes hlfmt hwmon induct interface keyboard_layout locking logfile loopback memory monitor mpsp outfile_check outfile pidfile potfile restore rp rp_cpu selftest slow_candidates shared status stdout straight terminal thread timer tuningdb usage user_options wordlist $(EMU_OBJS_ALL)

ifeq ($(ENABLE_BRAIN),1)
OBJS_ALL                += brain
endif

NATIVE_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.o)
LINUX_OBJS              := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.o)
WIN_OBJS                := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.o)

ifeq ($(USE_SYSTEM_LZMA),0)
OBJS_LZMA               := Alloc Lzma2Dec LzmaDec

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).WIN.o)
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
OBJS_ZLIB               := adler32 crc32 deflate inflate inffast inftrees trees gzread gzwrite gzclose zutil gzlib contrib/minizip/unzip contrib/minizip/ioapi

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_ZLIB),obj/$(OBJ).WIN.o)
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
OBJS_XXHASH             := xxhash

NATIVE_OBJS             += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).NATIVE.o)
LINUX_OBJS              += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).LINUX.o)
WIN_OBJS                += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).WIN.o)
endif
endif

##
## Targets: Native Compilation
##

default: $(HASHCAT_FRONTEND) modules

clean:
	$(RM) -f $(HASHCAT_FRONTEND)
	$(RM) -f $(HASHCAT_LIBRARY)
	$(RM) -rf modules/*.dSYM
	$(RM) -f modules/*.dll
	$(RM) -f modules/*.so
	$(RM) -f obj/*/*/*.o
	$(RM) -f obj/*.o
	$(RM) -f obj/*.a
	$(RM) -f *.bin *.exe
	$(RM) -f *.pid
	$(RM) -f *.restore
	$(RM) -f *.log
	$(RM) -f core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf *.dSYM
	$(RM) -rf kernels

distclean: clean
	$(RM) -f *.restore *.pot *.out *.log

##
## Targets: Linux install
##

# allow (whitelist) "make install" only on unix-based systems (also disallow cygwin/msys)

ifneq ($(findstring install,$(MAKECMDGOALS)),)
  ifeq (,$(filter $(UNAME),Linux FreeBSD Darwin))
    define ERROR_INSTALL_DISALLOWED
! The 'install' target is not allowed on this operating system ($(UNAME)). \
Only Linux, FreeBSD and Darwin can use the 'install' target
    endef

    $(error $(ERROR_INSTALL_DISALLOWED))
  endif
endif

ifeq ($(SHARED),1)
install: install_docs install_shared install_library install_library_dev install_kernels install_modules install_hashcat
else
install: install_docs install_shared                                     install_kernels install_modules install_hashcat
endif

# we need this extra target to make sure that for parallel builds (i.e. 2+ Makefile targets could possible run at the same time)
# the root folder of the shared directory is created first (and is a dependency for the targets that depend on it)

install_make_library_dev_root:
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_DEV_ROOT_FOLDER)

install_make_shared_root:
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_ROOT_FOLDER)

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

install_shared: install_make_shared_root
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)
	$(INSTALL) -m 644 hashcat.hctune                                        $(DESTDIR)$(SHARED_FOLDER)/
	$(INSTALL) -m 644 hashcat.hcstat2                                       $(DESTDIR)$(SHARED_FOLDER)/

install_kernels: install_shared
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/OpenCL
	$(FIND) OpenCL/   -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/OpenCL/{} \;
	$(FIND) OpenCL/   -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/OpenCL/{} \;

install_modules: install_shared modules
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/modules
	$(FIND) modules/  -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/modules/{} \;
	$(FIND) modules/  -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/modules/{} \;

install_library: $(HASHCAT_LIBRARY)
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_FOLDER)
	$(INSTALL) -m 755 $(HASHCAT_LIBRARY)                                    $(DESTDIR)$(LIBRARY_FOLDER)/

install_library_dev: install_make_library_dev_root
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(LIBRARY_DEV_FOLDER)
	$(FIND) include/  -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(LIBRARY_DEV_FOLDER)/{} \;
	$(FIND) include/  -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(LIBRARY_DEV_FOLDER)/{} \;

install_hashcat: $(HASHCAT_FRONTEND)
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(INSTALL_FOLDER)
	$(INSTALL) -m 755 $(HASHCAT_FRONTEND)                                   $(DESTDIR)$(INSTALL_FOLDER)/

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
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.NATIVE.o: $(DEPS_LZMA_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
obj/%.NATIVE.o: $(DEPS_ZLIB_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $(CFLAGS_ZLIB) $< -o $@ -fpic
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
obj/%.NATIVE.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic
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
	$(CC)    $(CFLAGS_NATIVE) $^ -o $@ $(HASHCAT_LIBRARY) $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
else
$(HASHCAT_FRONTEND): src/main.c obj/combined.NATIVE.a
	$(CC)    $(CFLAGS_NATIVE) $^ -o $@                    $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
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
MODULES_LIB   := $(patsubst src/modules/module_%.c, modules/module_%.$(MODULE_SUFFIX), $(MODULES_SRC))

ifeq ($(SHARED),1)
modules/module_%.$(MODULE_SUFFIX): src/modules/module_%.c $(HASHCAT_LIBRARY)
	$(CC)    $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)
else
modules/module_%.$(MODULE_SUFFIX): src/modules/module_%.c obj/combined.NATIVE.a
	$(CC)    $(CFLAGS_NATIVE) $^ -o $@ $(LFLAGS_NATIVE) -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)
endif

modules: $(MODULES_LIB)

##
## Cross Compilation (binary release version)
##

ifeq ($(UNAME),Linux)

##
## Compiler paths
##

CC_LINUX                := gcc
CC_WIN                  := x86_64-w64-mingw32-gcc

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

LFLAGS_CROSS_LINUX      := $(LFLAGS)
LFLAGS_CROSS_LINUX      += -lpthread
LFLAGS_CROSS_LINUX      += -ldl
LFLAGS_CROSS_LINUX      += -lm
LFLAGS_CROSS_WIN        := $(LFLAGS)
LFLAGS_CROSS_WIN        += -Wl,--dynamicbase
LFLAGS_CROSS_WIN        += -Wl,--nxcompat
LFLAGS_CROSS_WIN        += -lpsapi
LFLAGS_CROSS_WIN        += -lws2_32

##
## Targets
##

binaries: linux win

host_linux: hashcat.bin
host_win:   hashcat.exe

linux: host_linux modules_linux
win:   host_win   modules_win

##
## cross compiled modules
##

MODULES_LIB_LINUX   := $(patsubst src/modules/module_%.c, modules/module_%.so,  $(MODULES_SRC))
MODULES_LIB_WIN     := $(patsubst src/modules/module_%.c, modules/module_%.dll, $(MODULES_SRC))

modules_linux: $(MODULES_LIB_LINUX)
modules_win:   $(MODULES_LIB_WIN)

modules/module_%.so:  src/modules/module_%.c obj/combined.LINUX.a
	$(CC_LINUX)  $(CFLAGS_CROSS_LINUX) $^ -o $@ $(LFLAGS_CROSS_LINUX) -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)

modules/module_%.dll: src/modules/module_%.c obj/combined.WIN.a
	$(CC_WIN)    $(CFLAGS_CROSS_WIN)   $^ -o $@ $(LFLAGS_CROSS_WIN)   -shared -fPIC -D MODULE_INTERFACE_VERSION_CURRENT=$(MODULE_INTERFACE_VERSION)

##
## cross compiled hashcat
##

obj/%.LINUX.o: src/%.c
	$(CC_LINUX) $(CFLAGS_CROSS_LINUX) -c -o $@ $<

obj/%.WIN.o:   src/%.c
	$(CC_WIN)   $(CFLAGS_CROSS_WIN)   -c -o $@ $<

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.LINUX.o: $(DEPS_LZMA_PATH)/%.c
	$(CC_LINUX) $(CFLAGS_CROSS_LINUX) -c -o $@ $<

obj/%.WIN.o:   $(DEPS_LZMA_PATH)/%.c
	$(CC_WIN)   $(CFLAGS_CROSS_WIN)   -c -o $@ $<
endif

ifeq ($(USE_SYSTEM_ZLIB),0)
obj/%.LINUX.o: $(DEPS_ZLIB_PATH)/%.c
	$(CC_LINUX) $(CFLAGS_CROSS_LINUX) $(CFLAGS_ZLIB) -c -o $@ $<

obj/%.WIN.o:   $(DEPS_ZLIB_PATH)/%.c
	$(CC_WIN)   $(CFLAGS_CROSS_WIN) $(CFLAGS_ZLIB) -c -o $@ $<
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
obj/%.LINUX.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC_LINUX) $(CFLAGS_CROSS_LINUX) -c -o $@ $<

obj/%.WIN.o:   $(DEPS_XXHASH_PATH)/%.c
	$(CC_WIN)   $(CFLAGS_CROSS_WIN)   -c -o $@ $<
endif
endif

obj/combined.LINUX.a: $(LINUX_OBJS)
	$(AR_LINUX) rcs $@ $^

obj/combined.WIN.a: $(WIN_OBJS)
	$(AR_WIN) rcs $@ $^

hashcat.bin: src/main.c obj/combined.LINUX.a
	$(CC_LINUX) $(CFLAGS_CROSS_LINUX)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat.exe: src/main.c obj/combined.WIN.a $(WIN_ICONV)/lib/libiconv.a
	$(CC_WIN)   $(CFLAGS_CROSS_WIN)      -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat.dll: src/main.c obj/combined.WIN.a $(WIN_ICONV)/lib/libiconv.a
	$(CC_WIN)   $(CFLAGS_CROSS_WIN)      -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -shared

endif
