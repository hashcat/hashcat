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

MAKEFLAGS               += -l -j -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS               += -j 1
endif

##
## Native compiler paths
##

CC                      := gcc
FIND                    := find
INSTALL                 := install
RM                      := rm
SED                     := sed
SED_IN_PLACE            := -i

ifeq ($(UNAME),Darwin)
CC                      := clang
# the sed -i option of macOS requires a parameter for the backup file (we just use "")
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

## To compile win-iconv with mingw clone from here: https://github.com/win-iconv/win-iconv
##
## Then patch the makefile with the patches from tools/win-iconv-*.diff and run make install
##

WIN_ICONV_32            := /opt/win-iconv-32
WIN_ICONV_64            := /opt/win-iconv-64

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
## Cross compiler paths
##

CC_LINUX_32             := gcc
CC_LINUX_64             := gcc

CC_WIN_32               := i686-w64-mingw32-gcc
CC_WIN_64               := x86_64-w64-mingw32-gcc

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

ifeq ($(DEBUG),0)
CFLAGS                  += -O2
ifneq ($(UNAME),Darwin)
LFLAGS                  += -s
endif
else
ifeq ($(DEBUG),1)
CFLAGS                  += -DDEBUG -Og -ggdb
else
ifeq ($(DEBUG),2)
CFLAGS                  += -DDEBUG -Og -ggdb
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
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
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
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
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
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_NATIVE           += -lpsapi
LFLAGS_NATIVE           += -liconv
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_NATIVE           += -lpsapi
LFLAGS_NATIVE           += -liconv
LFLAGS_NATIVE           += -lws2_32
endif # MSYS2

##
## Cross compilation targets
##

CFLAGS_CROSS_LINUX32    := $(CFLAGS)
CFLAGS_CROSS_LINUX32    += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_LINUX32    += -m32
CFLAGS_CROSS_LINUX32    += -DWITH_HWMON
CFLAGS_CROSS_LINUX64    := $(CFLAGS)
CFLAGS_CROSS_LINUX64    += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_LINUX64    += -m64
CFLAGS_CROSS_LINUX64    += -DWITH_HWMON
CFLAGS_CROSS_WIN32      := $(CFLAGS)
CFLAGS_CROSS_WIN32      += -D__MINGW_USE_VC2005_COMPAT #hack to get 64-bit time_t
CFLAGS_CROSS_WIN32      += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_WIN32      += -I$(WIN_ICONV_32)/include/
CFLAGS_CROSS_WIN32      += -m32
CFLAGS_CROSS_WIN32      += -DWITH_HWMON
CFLAGS_CROSS_WIN64      := $(CFLAGS)
CFLAGS_CROSS_WIN64      += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_WIN64      += -I$(WIN_ICONV_64)/include/
CFLAGS_CROSS_WIN64      += -m64
CFLAGS_CROSS_WIN64      += -DWITH_HWMON

LFLAGS_CROSS_LINUX32    := $(LFLAGS)
LFLAGS_CROSS_LINUX32    += -lpthread
LFLAGS_CROSS_LINUX32    += -ldl
LFLAGS_CROSS_LINUX32    += -lm
LFLAGS_CROSS_LINUX64    := $(LFLAGS)
LFLAGS_CROSS_LINUX64    += -lpthread
LFLAGS_CROSS_LINUX64    += -ldl
LFLAGS_CROSS_LINUX64    += -lm
LFLAGS_CROSS_WIN32      := $(LFLAGS)
LFLAGS_CROSS_WIN32      += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_CROSS_WIN32      += -lpsapi
LFLAGS_CROSS_WIN32      += -lws2_32
LFLAGS_CROSS_WIN64      := $(LFLAGS)
LFLAGS_CROSS_WIN64      += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_CROSS_WIN64      += -lpsapi
LFLAGS_CROSS_WIN64      += -lws2_32

##
## Objects
##

OBJS_ALL                := affinity autotune benchmark bitmap bitops combinator common convert cpt cpu_aes cpu_crc32 cpu_des cpu_md4 cpu_md5 cpu_sha1 cpu_sha256 debugfile dictstat dispatch dynloader event ext_ADL ext_nvapi ext_nvml ext_OpenCL ext_sysfs ext_lzma filehandling folder hashcat hashes hlfmt hwmon induct interface locking logfile loopback memory monitor mpsp opencl outfile_check outfile pidfile potfile restore rp rp_cpu rp_kernel_on_cpu rp_kernel_on_cpu_optimized selftest slow_candidates shared status stdout straight terminal thread timer tuningdb usage user_options wordlist

ifeq ($(ENABLE_BRAIN),1)
OBJS_ALL                += brain
endif

NATIVE_STATIC_OBJS      := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.STATIC.o)
NATIVE_SHARED_OBJS      := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.SHARED.o)

LINUX_32_OBJS           := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.32.o)
LINUX_64_OBJS           := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.64.o)

WIN_32_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.32.o)
WIN_64_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.64.o)

ifeq ($(USE_SYSTEM_LZMA),0)
OBJS_LZMA               := Alloc Lzma2Dec LzmaDec

NATIVE_STATIC_OBJS      += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).NATIVE.STATIC.o)
NATIVE_SHARED_OBJS      += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).NATIVE.SHARED.o)

LINUX_32_OBJS           += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LINUX.32.o)
LINUX_64_OBJS           += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).LINUX.64.o)

WIN_32_OBJS             += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).WIN.32.o)
WIN_64_OBJS             += $(foreach OBJ,$(OBJS_LZMA),obj/$(OBJ).WIN.64.o)
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
OBJS_XXHASH             := xxhash

NATIVE_STATIC_OBJS      += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).NATIVE.STATIC.o)
NATIVE_SHARED_OBJS      += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).NATIVE.SHARED.o)

LINUX_32_OBJS           += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).LINUX.32.o)
LINUX_64_OBJS           += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).LINUX.64.o)

WIN_32_OBJS             += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).WIN.32.o)
WIN_64_OBJS             += $(foreach OBJ,$(OBJS_XXHASH),obj/$(OBJ).WIN.64.o)
endif
endif

##
## Targets: Native Compilation
##

default: $(HASHCAT_FRONTEND)

clean:
	$(RM) -f $(HASHCAT_FRONTEND)
	$(RM) -f $(HASHCAT_LIBRARY)
	$(RM) -f obj/*.o
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
## Targets: Cross Compilation (for binary release version)
##

binaries: linux32 linux64 win32 win64

linux32: hashcat32.bin
linux64: hashcat64.bin

win32: hashcat32.exe
win64: hashcat64.exe

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
install: install_docs install_shared install_library install_library_dev install_hashcat
else
install: install_docs install_shared                                     install_hashcat
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
	$(INSTALL) -m 755 -d                                                    $(DESTDIR)$(SHARED_FOLDER)/OpenCL
	$(FIND) OpenCL/   -mindepth 1 -type d -execdir $(INSTALL) -m 755 -d     $(DESTDIR)$(SHARED_FOLDER)/OpenCL/{} \;
	$(FIND) OpenCL/   -mindepth 1 -type f -execdir $(INSTALL) -m 644 {}     $(DESTDIR)$(SHARED_FOLDER)/OpenCL/{} \;

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

obj/%.NATIVE.STATIC.o: src/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@

obj/%.NATIVE.SHARED.o: src/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.NATIVE.STATIC.o: $(DEPS_LZMA_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@

obj/%.NATIVE.SHARED.o: $(DEPS_LZMA_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
obj/%.NATIVE.STATIC.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@

obj/%.NATIVE.SHARED.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic
endif
endif

ifeq ($(UNAME),Darwin)
$(HASHCAT_LIBRARY): $(NATIVE_SHARED_OBJS)
	$(CC)                     $^ -o $@                    $(LFLAGS_NATIVE) -shared -install_name $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY) -current_version $(VERSION_PURE) -compatibility_version $(VERSION_PURE)
else
$(HASHCAT_LIBRARY): $(NATIVE_SHARED_OBJS)
	$(CC)                     $^ -o $@                    $(LFLAGS_NATIVE) -shared -Wl,-soname,$(HASHCAT_LIBRARY)
endif

ifeq ($(SHARED),1)
$(HASHCAT_FRONTEND): src/main.c $(HASHCAT_LIBRARY)
	$(CC)    $(CFLAGS_NATIVE) $^ -o $@ $(HASHCAT_LIBRARY) $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
else
$(HASHCAT_FRONTEND): src/main.c $(NATIVE_STATIC_OBJS)
	$(CC)    $(CFLAGS_NATIVE) $^ -o $@                    $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
endif

##
## cross compiled hashcat
##

obj/%.LINUX.32.o: src/%.c
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX32) -c -o $@ $<

obj/%.LINUX.64.o: src/%.c
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX64) -c -o $@ $<

obj/%.WIN.32.o:   src/%.c
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)   -c -o $@ $<

obj/%.WIN.64.o:   src/%.c
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)   -c -o $@ $<

ifeq ($(USE_SYSTEM_LZMA),0)
obj/%.LINUX.32.o: $(DEPS_LZMA_PATH)/%.c
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX32) -c -o $@ $<

obj/%.LINUX.64.o: $(DEPS_LZMA_PATH)/%.c
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX64) -c -o $@ $<

obj/%.WIN.32.o:   $(DEPS_LZMA_PATH)/%.c
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)   -c -o $@ $<

obj/%.WIN.64.o:   $(DEPS_LZMA_PATH)/%.c
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)   -c -o $@ $<
endif

ifeq ($(USE_SYSTEM_XXHASH),0)
ifeq ($(ENABLE_BRAIN),1)
obj/%.LINUX.32.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX32) -c -o $@ $<

obj/%.LINUX.64.o: $(DEPS_XXHASH_PATH)/%.c
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX64) -c -o $@ $<

obj/%.WIN.32.o:   $(DEPS_XXHASH_PATH)/%.c
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)   -c -o $@ $<

obj/%.WIN.64.o:   $(DEPS_XXHASH_PATH)/%.c
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)   -c -o $@ $<
endif
endif

hashcat32.bin: src/main.c $(LINUX_32_OBJS)
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX32)    -o $@ $^ $(LFLAGS_CROSS_LINUX32) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat64.bin: src/main.c $(LINUX_64_OBJS)
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX64)    -o $@ $^ $(LFLAGS_CROSS_LINUX64) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat32.exe: src/main.c $(WIN_32_OBJS) $(WIN_ICONV_32)/lib/libiconv.a
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)      -o $@ $^ $(LFLAGS_CROSS_WIN32)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat64.exe: src/main.c $(WIN_64_OBJS) $(WIN_ICONV_64)/lib/libiconv.a
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)      -o $@ $^ $(LFLAGS_CROSS_WIN64)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat32.dll: src/main.c $(WIN_32_OBJS)
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)      -o $@ $^ $(LFLAGS_CROSS_WIN32)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -shared

hashcat64.dll: src/main.c $(WIN_64_OBJS)
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)      -o $@ $^ $(LFLAGS_CROSS_WIN64)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -shared
