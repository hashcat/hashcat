##
## Author......: See docs/credits.txt
## License.....: MIT
##

SHARED                  := 0
DEBUG                   := 0
PRODUCTION              := 1

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
## Installation paths (Linux only)
##

DESTDIR                 ?=
PREFIX                  ?= /usr/local

INSTALL_FOLDER          ?= $(PREFIX)/bin
LIBRARY_FOLDER          ?= $(PREFIX)/lib
SHARED_FOLDER           ?= $(PREFIX)/share/hashcat
DOCUMENT_FOLDER         ?= $(PREFIX)/share/doc/hashcat

##
## Filenames for library and frontend
##

HASHCAT_FRONTEND        := hashcat
HASHCAT_LIBRARY         := libhashcat.so

ifeq ($(UNAME),CYGWIN)
HASHCAT_FRONTEND        := hashcat.exe
HASHCAT_LIBRARY         := hashcat.dll
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
HASHCAT_FRONTEND        := hashcat.exe
HASHCAT_LIBRARY         := hashcat.dll
endif # MSYS2

##
## Dependencies
## You may ignore them if you're compiling only a native binary and
## You have your own headers somewhere, for example: apt-get install opencl-headers
##

OPENCL_HEADERS_KHRONOS  := deps/OpenCL-Headers

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
# the sed -i option of OSX requires a parameter for the backup file (we just use "")
SED_IN_PLACE            := -i ""
endif

ifeq ($(UNAME),FreeBSD)
CC                      := cc
SED                     := gsed
endif

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

VERSION_EXPORT          := $Format:%D$
VERSION_TAG             := $(shell test -d .git && git describe --tags --dirty=+ || echo "$(VERSION_EXPORT)"|cut -d, -f2|$(SED) -r 's|.* (\w+/)?([^ ]+)|\2|')

##
## General compiler and linker options
##

CFLAGS                  += -pipe -std=c99 -Iinclude/ -Iinclude/lzma_sdk/ -IOpenCL/

ifeq ($(PRODUCTION),0)
CFLAGS                  += -W
CFLAGS                  += -Wall
CFLAGS                  += -Wextra
CFLAGS                  += -Wfloat-equal
CFLAGS                  += -Wundef
CFLAGS                  += -Wshadow
CFLAGS                  += -Wmissing-declarations
CFLAGS                  += -Wmissing-prototypes
CFLAGS                  += -Wpointer-arith
CFLAGS                  += -Wstrict-prototypes
CFLAGS                  += -Waggregate-return
CFLAGS                  += -Wswitch-enum
CFLAGS                  += -Wunreachable-code
CFLAGS                  += -Winit-self
CFLAGS                  += -Werror-implicit-function-declaration
CFLAGS                  += -Wformat
CFLAGS                  += -ftrapv

# the following compiler options produce warnings that should be fixed at some time

#CFLAGS                  += -Wsizeof-pointer-memaccess
#CFLAGS                  += -Wcast-align
#CFLAGS                  += -Wcast-qual
#CFLAGS                  += -Wsign-conversion
#CFLAGS                  += -Wwrite-strings
#CFLAGS                  += -pedantic
endif

# default linux and freebsd thread stack size is 2MB
# default windows thread stack size is 1MB
# default OSX thread stack size is 512kB
# unfortionally, this option isn't supported by older GCC and clang versions

#CFLAGS                  += -Wstack-usage=524288

LFLAGS                  := $(LDFLAGS)

ifeq ($(DEBUG),0)
CFLAGS                  += -O2
LFLAGS                  += -s
else
ifeq ($(DEBUG),1)
CFLAGS                  += -DDEBUG -g -ggdb
else
ifeq ($(DEBUG),2)
CFLAGS                  += -DDEBUG -g -ggdb
CFLAGS                  += -fsanitize=address -fno-omit-frame-pointer
endif
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
LFLAGS_NATIVE           += -lpthread -ldl
endif # Linux

ifeq ($(UNAME),FreeBSD)
ifndef PORTNAME
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -lpthread
endif
endif # FreeBSD

ifeq ($(UNAME),Darwin)
export MACOSX_DEPLOYMENT_TARGET=10.9
CFLAGS_NATIVE           := $(CFLAGS)
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -framework OpenCL
LFLAGS_NATIVE           += -lpthread
endif # Darwin

ifeq ($(UNAME),CYGWIN)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_NATIVE           += -lpsapi
endif # CYGWIN

ifeq ($(UNAME),MSYS2)
CFLAGS_NATIVE           := $(CFLAGS)
CFLAGS_NATIVE           += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_NATIVE           += -DWITH_HWMON
LFLAGS_NATIVE           := $(LFLAGS)
LFLAGS_NATIVE           += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_NATIVE           += -lpsapi
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
CFLAGS_CROSS_WIN32      += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_WIN32      += -m32
CFLAGS_CROSS_WIN32      += -DWITH_HWMON
CFLAGS_CROSS_WIN64      := $(CFLAGS)
CFLAGS_CROSS_WIN64      += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_WIN64      += -m64
CFLAGS_CROSS_WIN64      += -DWITH_HWMON

LFLAGS_CROSS_LINUX32    := $(LFLAGS)
LFLAGS_CROSS_LINUX32    += -lpthread -ldl
LFLAGS_CROSS_LINUX64    := $(LFLAGS)
LFLAGS_CROSS_LINUX64    += -lpthread -ldl
LFLAGS_CROSS_WIN32      := $(LFLAGS)
LFLAGS_CROSS_WIN32      += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_CROSS_WIN32      += -lpsapi
LFLAGS_CROSS_WIN64      := $(LFLAGS)
LFLAGS_CROSS_WIN64      += -Wl,--dynamicbase -Wl,--nxcompat
LFLAGS_CROSS_WIN64      += -lpsapi

##
## Objects
##

OBJS_ALL                := affinity autotune benchmark bitmap bitops combinator common convert cpt cpu_aes cpu_crc32 cpu_des cpu_md4 cpu_md5 cpu_sha1 cpu_sha256 debugfile dictstat dispatch dynloader event ext_ADL ext_nvapi ext_nvml ext_OpenCL ext_sysfs ext_xnvctrl ext_lzma lzma_sdk/Alloc lzma_sdk/Lzma2Dec lzma_sdk/LzmaDec filehandling folder hashcat hashes hlfmt hwmon induct interface locking logfile loopback memory monitor mpsp opencl outfile_check outfile pidfile potfile restore rp rp_cpu rp_kernel_on_cpu shared status stdout straight terminal thread timer tuningdb usage user_options weak_hash wordlist

NATIVE_STATIC_OBJS      := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.STATIC.o)
NATIVE_SHARED_OBJS      := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.SHARED.o)

LINUX_32_OBJS           := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.32.o)
LINUX_64_OBJS           := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.64.o)

WIN_32_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.32.o)
WIN_64_OBJS             := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.64.o)

##
## Targets: Native Compilation
##

default: $(HASHCAT_FRONTEND)

clean:
	$(RM) -f obj/*.o obj/lzma_sdk/*.o *.bin *.exe *.so *.dll *.restore *.out *.pid *.log hashcat core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf *.dSYM
	$(RM) -rf kernels

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
## How to make /usr/bin/install doing recursive??
##

ifeq ($(SHARED),1)
install: install_docs install_shared install_library install_hashcat
else
install: install_docs install_shared                 install_hashcat
endif

install_docs:
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/docs
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/charsets
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/masks
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/rules
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/extra
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion
	$(INSTALL) -m 644 example.dict                          $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example0.hash                         $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example400.hash                       $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example500.hash                       $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 example0.sh                           $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 example400.sh                         $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 example500.sh                         $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 extra/tab_completion/hashcat.sh       $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/
	$(INSTALL) -m 644 extra/tab_completion/howto.txt        $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/
	$(INSTALL) -m 755 extra/tab_completion/install          $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/
	$(FIND) docs/     -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) docs/     -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) charsets/ -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) charsets/ -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) masks/    -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) masks/    -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) rules/    -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) rules/    -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(SED) $(SED_IN_PLACE) 's/\.\/hashcat/hashcat/'         $(DESTDIR)$(DOCUMENT_FOLDER)/example0.sh
	$(SED) $(SED_IN_PLACE) 's/\.\/hashcat/hashcat/'         $(DESTDIR)$(DOCUMENT_FOLDER)/example400.sh
	$(SED) $(SED_IN_PLACE) 's/\.\/hashcat/hashcat/'         $(DESTDIR)$(DOCUMENT_FOLDER)/example500.sh

install_shared:
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)/OpenCL
	$(INSTALL) -m 644 hashcat.hcstat                        $(DESTDIR)$(SHARED_FOLDER)/
	$(INSTALL) -m 644 hashcat.hctune                        $(DESTDIR)$(SHARED_FOLDER)/
	$(FIND) OpenCL/   -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) OpenCL/   -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(SHARED_FOLDER)/{}   \;

install_library: $(HASHCAT_LIBRARY)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(LIBRARY_FOLDER)
	$(INSTALL) -m 755 $(HASHCAT_LIBRARY)                    $(DESTDIR)$(LIBRARY_FOLDER)/

install_hashcat: $(HASHCAT_FRONTEND)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(INSTALL_FOLDER)
	$(INSTALL) -m 755 $(HASHCAT_FRONTEND)                   $(DESTDIR)$(INSTALL_FOLDER)/

uninstall:
	$(RM) -f  $(DESTDIR)$(INSTALL_FOLDER)/$(HASHCAT_FRONTEND)
	$(RM) -f  $(DESTDIR)$(LIBRARY_FOLDER)/$(HASHCAT_LIBRARY)
	$(RM) -rf $(DESTDIR)$(SHARED_FOLDER)
	$(RM) -rf $(DESTDIR)$(DOCUMENT_FOLDER)

##
## native compiled hashcat library and frontend
##

obj/%.NATIVE.STATIC.o: src/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@

obj/%.NATIVE.SHARED.o: src/%.c
	$(CC) -c $(CFLAGS_NATIVE) $< -o $@ -fpic

$(HASHCAT_LIBRARY): $(NATIVE_SHARED_OBJS)
	$(CC)                                $^            $(LFLAGS_NATIVE) -o $@ -shared

ifeq ($(SHARED),1)
$(HASHCAT_FRONTEND): src/main.c $(HASHCAT_LIBRARY)
	$(CC)    $(CFLAGS_NATIVE) $^ -L. -lhashcat $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\" -o $@
else
$(HASHCAT_FRONTEND): src/main.c $(NATIVE_STATIC_OBJS)
	$(CC)    $(CFLAGS_NATIVE) $^               $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\" -o $@
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

hashcat32.bin: src/main.c $(LINUX_32_OBJS)
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX32)    -o $@ $^ $(LFLAGS_CROSS_LINUX32) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat64.bin: src/main.c $(LINUX_64_OBJS)
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX64)    -o $@ $^ $(LFLAGS_CROSS_LINUX64) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat32.exe: src/main.c $(WIN_32_OBJS)
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)      -o $@ $^ $(LFLAGS_CROSS_WIN32)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat64.exe: src/main.c $(WIN_64_OBJS)
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)      -o $@ $^ $(LFLAGS_CROSS_WIN64)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat32.dll: src/main.c $(WIN_32_OBJS)
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN32)      -o $@ $^ $(LFLAGS_CROSS_WIN32)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -shared

hashcat64.dll: src/main.c $(WIN_64_OBJS)
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN64)      -o $@ $^ $(LFLAGS_CROSS_WIN64)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -shared
