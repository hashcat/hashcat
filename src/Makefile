##
## Author......: See docs/credits.txt
## License.....: MIT
##

PROG_NAME                := hashcat

##
## Detect Operating System
##

UNAME                    := $(shell uname -s)

# we need to strip the windows version number to be able to build hashcat on cygwin hosts
UNAME                    := $(patsubst CYGWIN_NT-%,CYGWIN_NT-,$(UNAME))

ifeq (,$(filter $(UNAME),Linux Darwin CYGWIN_NT- FreeBSD))
$(error "! Your Operating System ($(UNAME)) is not supported by $(PROG_NAME) Makefile")
endif

ifeq ($(DEBUG),1)
$(warning "## Detected Operating System : $(UNAME)")
endif

##
## Makefile flags
##

MAKEFLAGS                += -l -j -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS                += -j 1
endif

##
## Installation paths (Linux only)
##

DESTDIR                  ?=
PREFIX                   ?= /usr/local

INSTALL_FOLDER           ?= $(PREFIX)/bin
SHARED_FOLDER            ?= $(PREFIX)/share/$(PROG_NAME)
DOCUMENT_FOLDER          ?= $(PREFIX)/share/doc/$(PROG_NAME)

##
## Dependencies
## You may ignore them if you're compiling only a native binary and
## You have your own headers somewhere, for example: apt-get install opencl-headers
##

OPENCL_HEADERS_KHRONOS   := deps/OpenCL-Headers

##
## Native compiler paths
##

CC                       := gcc
FIND                     := find
INSTALL                  := install
RM                       := rm
SED                      := sed
ifeq ($(UNAME),Darwin)
SED                      := gsed
endif
ifeq ($(UNAME),FreeBSD)
CC                       := cc
SED                      := gsed
endif

##
## Cross compiler paths
##

CC_LINUX_32              := gcc
CC_LINUX_64              := gcc

CC_WIN_32                := i686-w64-mingw32-gcc
CC_WIN_64                := x86_64-w64-mingw32-gcc

##
## Misc stuff
##

COMPTIME                 := $(shell date +%s)

VERSION_EXPORT           := $Format:%D$
VERSION_TAG              := $(shell test -d .git && git describe --tags --dirty=+ || echo "$(VERSION_EXPORT)"|cut -d, -f2|$(SED) -r 's|.* (\w+/)?([^ ]+)|\2|')

##
## Compiler flags
##

CFLAGS                   += -pipe -W -Wall -std=c99 -Iinclude/ -IOpenCL/ -I$(OPENCL_HEADERS_KHRONOS)/

ifndef DEBUG
CFLAGS                   += -O2
else
CFLAGS                   += -DDEBUG -g -ggdb
ifeq ($(DEBUG),2)
CFLAGS                   += -fsanitize=address -fno-omit-frame-pointer
endif
endif

##
## Native compilation target
##

BINARY_NATIVE            := $(PROG_NAME)

ifeq ($(UNAME),Darwin)
export MACOSX_DEPLOYMENT_TARGET=10.9
CFLAGS_NATIVE            :=
CFLAGS_NATIVE            += $(CFLAGS)
LFLAGS_NATIVE            := -lpthread
LFLAGS_NATIVE            += $(LDFLAGS)
endif # darwin

ifeq ($(UNAME),Linux)
CFLAGS_NATIVE            :=
ifndef DEBUG
CFLAGS_NATIVE            += -s
endif
CFLAGS_NATIVE            += $(CFLAGS)
LFLAGS_NATIVE            := -lpthread -ldl
CFLAGS_NATIVE            += -DWITH_HWMON
LFLAGS_NATIVE            += $(LDFLAGS)
endif # linux

ifeq ($(UNAME),FreeBSD)
CFLAGS_NATIVE            :=
CFLAGS_NATIVE            += $(CFLAGS)
LFLAGS_NATIVE            := -lpthread
LFLAGS_NATIVE            += $(LDFLAGS)
endif # freebsd

##
## Cross compilation target
##

CFLAGS_CROSS_LINUX       :=
ifndef DEBUG
CFLAGS_CROSS_LINUX       += -s
endif
CFLAGS_CROSS_LINUX       += $(CFLAGS)
CFLAGS_CROSS_LINUX       += -DWITH_HWMON

#CFLAGS_CROSS_WIN         := -D_WIN -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1
CFLAGS_CROSS_WIN         :=
ifndef DEBUG
CFLAGS_CROSS_WIN         += -s
endif
CFLAGS_CROSS_WIN         += $(filter-out -fsanitize=address,$(CFLAGS))
CFLAGS_CROSS_WIN         += -DWITH_HWMON

CFLAGS_CROSS_32          := -m32
CFLAGS_CROSS_64          := -m64

LFLAGS_CROSS_LINUX       := -lpthread -ldl
LFLAGS_CROSS_WIN         := -lpsapi

##
## Objects
##

OBJS_ALL                 := affinity autotune benchmark bitmap bitops combinator common convert cpt cpu_aes cpu_crc32 cpu_des cpu_md5 cpu_sha1 cpu_sha256 debugfile dictstat dispatch dynloader ext_ADL ext_nvapi ext_nvml ext_OpenCL ext_xnvctrl filehandling folder hashcat hashes hlfmt hwmon induct interface locking logfile logging loopback memory monitor mpsp opencl outfile_check outfile potfile restore rp rp_cpu rp_kernel_on_cpu shared status stdout straight terminal thread timer tuningdb usage user_options weak_hash wordlist

NATIVE_OBJS              := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).NATIVE.o)

LINUX_32_OBJS            := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.32.o)
LINUX_64_OBJS            := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).LINUX.64.o)

# Windows CRT file globbing:

CRT_GLOB_32              :=
CRT_GLOB_64              :=
CRT_GLOB_INCLUDE_FOLDER  := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CRT_GLOB_INCLUDE_FOLDER)/win_file_globbing.mk

WIN_32_OBJS              := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.32.o) $(CRT_GLOB_32)
WIN_64_OBJS              := $(foreach OBJ,$(OBJS_ALL),obj/$(OBJ).WIN.64.o) $(CRT_GLOB_64)

##
## Targets: Global
##

native: hashcat

binaries: linux32 linux64 win32 win64

clean:
	$(RM) -f obj/*.o *.bin *.exe *.restore *.out *.pot *.log hashcat core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf *.dSYM
	$(RM) -rf kernels

linux32: hashcat32.bin
linux64: hashcat64.bin

win32: hashcat32.exe
win64: hashcat64.exe

##
## Targets: Linux install
## How to make /usr/bin/install doing recursive??
##

install: native
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(INSTALL_FOLDER)
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/docs
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/extra
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)/charsets
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)/masks
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)/OpenCL
	$(INSTALL) -m 755 -d                                    $(DESTDIR)$(SHARED_FOLDER)/rules
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
	$(INSTALL) -m 644 hashcat.hcstat                        $(DESTDIR)$(SHARED_FOLDER)/
	$(INSTALL) -m 644 hashcat.hctune                        $(DESTDIR)$(SHARED_FOLDER)/
	$(INSTALL) -m 755 $(BINARY_NATIVE)                      $(DESTDIR)$(INSTALL_FOLDER)/
	$(FIND) docs/     -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) charsets/ -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) masks/    -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) OpenCL/   -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) rules/    -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) docs/     -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \;
	$(FIND) charsets/ -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) masks/    -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) OpenCL/   -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(FIND) rules/    -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(SHARED_FOLDER)/{}   \;
	$(SED) -i 's/\.\/hashcat/hashcat/'                      $(DESTDIR)$(DOCUMENT_FOLDER)/example0.sh
	$(SED) -i 's/\.\/hashcat/hashcat/'                      $(DESTDIR)$(DOCUMENT_FOLDER)/example400.sh
	$(SED) -i 's/\.\/hashcat/hashcat/'                      $(DESTDIR)$(DOCUMENT_FOLDER)/example500.sh

uninstall:
	$(RM) -f  $(DESTDIR)$(INSTALL_FOLDER)/$(BINARY_NATIVE)
	$(RM) -rf $(DESTDIR)$(SHARED_FOLDER)
	$(RM) -rf $(DESTDIR)$(DOCUMENT_FOLDER)

##
## native compiled hashcat
##

obj/%.NATIVE.o:   src/%.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(BINARY_NATIVE):       src/main.c $(NATIVE_OBJS)
	$(CC) $(CFLAGS_NATIVE)    -o $(BINARY_NATIVE) $^ $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

##
## cross compiled hashcat for binary release version
##

obj/%.LINUX.32.o: src/%.c
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.LINUX.64.o: src/%.c
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64) -c -o $@ $<

obj/%.WIN.32.o:   src/%.c
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.WIN.64.o:   src/%.c
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64) -c -o $@ $<

hashcat32.bin: src/main.c $(LINUX_32_OBJS)
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat64.bin: src/main.c $(LINUX_64_OBJS)
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat32.exe: src/main.c $(WIN_32_OBJS)
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat64.exe: src/main.c $(WIN_64_OBJS)
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"
