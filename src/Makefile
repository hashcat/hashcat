##
## Authors.....: Jens Steube <jens.steube@gmail.com>
##               Gabriele Gristina <matrix@hashcat.net>
##               magnum <john.magnum@hushmail.com>
##
## License.....: MIT
##

PROG_NAME                := hashcat

##
## Detect Operating System
##

UNAME                    := $(shell uname -s)

ifeq (,$(filter $(UNAME),Linux Darwin))
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
## You may ignore them if you have your own headers somewhere
##

OPENCL_HEADERS_KHRONOS   := deps/OpenCL-Headers

##
## Native compiler paths
##

CP                       := cp
RM                       := rm
INSTALL                  := install

CC_NATIVE                := gcc

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
VERSION_TAG              := $(shell test -d .git && git describe --tags --dirty=+ || echo "$(VERSION_EXPORT)"|cut -d, -f2|sed -r 's|.* (\w+/)?([^ ]+)|\2|')

##
## Compiler flags
##

CFLAGS                   := -pipe -W -Wall -std=c99 -Iinclude/ -IOpenCL/ -I$(OPENCL_HEADERS_KHRONOS)/

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
BINARY_NATIVE            := $(BINARY_NATIVE).app
CFLAGS_NATIVE            := -D_POSIX -DOSX
CFLAGS_NATIVE            += $(CFLAGS)
LFLAGS_NATIVE            := -lpthread
endif # darwin

ifeq ($(UNAME),Linux)
CFLAGS_NATIVE            := -D_POSIX -DLINUX
ifndef DEBUG
CFLAGS_NATIVE            += -s
endif
CFLAGS_NATIVE            += $(CFLAGS)
LFLAGS_NATIVE            := -lpthread -ldl
CFLAGS_NATIVE            += -DHAVE_HWMON
endif # linux

##
## Cross compilation target
##

CFLAGS_CROSS_LINUX       := -D_POSIX -DLINUX

ifndef DEBUG
CFLAGS_CROSS_LINUX       += -s
endif

CFLAGS_CROSS_LINUX       += $(CFLAGS)
CFLAGS_CROSS_LINUX       += -DHAVE_HWMON

CFLAGS_CROSS_WIN         := -D_WIN -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1

ifndef DEBUG
CFLAGS_CROSS_WIN         += -s
endif

CFLAGS_CROSS_WIN         += $(filter-out -fsanitize=address,$(CFLAGS))
CFLAGS_CROSS_WIN         += -DHAVE_HWMON

CFLAGS_CROSS_32          := -m32
CFLAGS_CROSS_64          := -m64

LFLAGS_CROSS_LINUX       := -lpthread -ldl
LFLAGS_CROSS_WIN         := -lpsapi

##
## Objects
##

NATIVE_OBJS              := obj/ext_OpenCL.NATIVE.o obj/shared.NATIVE.o obj/rp_kernel_on_cpu.NATIVE.o

ifeq ($(UNAME),Linux)
NATIVE_OBJS              += obj/ext_ADL.NATIVE.o
NATIVE_OBJS              += obj/ext_nvapi.NATIVE.o
NATIVE_OBJS              += obj/ext_nvml.NATIVE.o
endif

LINUX_32_OBJS            := obj/ext_OpenCL.LINUX.32.o obj/shared.LINUX.32.o obj/rp_kernel_on_cpu.LINUX.32.o obj/ext_ADL.LINUX.32.o obj/ext_nvml.LINUX.32.o obj/ext_nvapi.LINUX.32.o
LINUX_64_OBJS            := obj/ext_OpenCL.LINUX.64.o obj/shared.LINUX.64.o obj/rp_kernel_on_cpu.LINUX.64.o obj/ext_ADL.LINUX.64.o obj/ext_nvml.LINUX.64.o obj/ext_nvapi.LINUX.64.o

## may need to adjust according to your mingw distribution
CRT_GLOB_32              := /usr/i686-w64-mingw32/lib/CRT_glob.o
CRT_GLOB_64              := /usr/x86_64-w64-mingw32/lib/CRT_glob.o

WIN_32_OBJS              := obj/ext_OpenCL.WIN.32.o   obj/shared.WIN.32.o   obj/rp_kernel_on_cpu.WIN.32.o   obj/ext_ADL.WIN.32.o   obj/ext_nvml.WIN.32.o   obj/ext_nvapi.WIN.32.o   $(CRT_GLOB_32)
WIN_64_OBJS              := obj/ext_OpenCL.WIN.64.o   obj/shared.WIN.64.o   obj/rp_kernel_on_cpu.WIN.64.o   obj/ext_ADL.WIN.64.o   obj/ext_nvml.WIN.64.o   obj/ext_nvapi.WIN.64.o   $(CRT_GLOB_64)

##
## Targets: Global
##

native: hashcat

binaries: linux32 linux64 win32 win64

clean:
	$(RM) -f obj/*.o *.bin *.exe *.app *.restore *.out *.pot *.dictstat *.log hashcat core
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
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(DOCUMENT_FOLDER)
	$(CP) -a docs/*                                 $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(CP) -a example*.sh                            $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(CP) -a example*.hash                          $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example.dict                  $(DESTDIR)$(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(DOCUMENT_FOLDER)/extra
	$(CP) -a extra/*                                $(DESTDIR)$(DOCUMENT_FOLDER)/extra/
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(SHARED_FOLDER)
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(SHARED_FOLDER)/charsets
	$(CP) -a charsets/*                             $(DESTDIR)$(SHARED_FOLDER)/charsets/
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(SHARED_FOLDER)/masks
	$(CP) -a masks/*                                $(DESTDIR)$(SHARED_FOLDER)/masks/
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(SHARED_FOLDER)/OpenCL
	$(CP) -a OpenCL/*                               $(DESTDIR)$(SHARED_FOLDER)/OpenCL/
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(SHARED_FOLDER)/rules
	$(CP) -a rules/*                                $(DESTDIR)$(SHARED_FOLDER)/rules/
	$(INSTALL) -m 644 hashcat.hcstat                $(DESTDIR)$(SHARED_FOLDER)/
	$(INSTALL) -m 644 hashcat.hctune                $(DESTDIR)$(SHARED_FOLDER)/
	$(INSTALL) -m 755 -d                            $(DESTDIR)$(INSTALL_FOLDER)
	$(INSTALL) -m 755 $(BINARY_NATIVE)              $(DESTDIR)$(INSTALL_FOLDER)/

uninstall:
	$(RM) -f  $(DESTDIR)$(INSTALL_FOLDER)/$(BINARY_NATIVE)
	$(RM) -rf $(DESTDIR)$(SHARED_FOLDER)
	$(RM) -rf $(DESTDIR)$(DOCUMENT_FOLDER)

##
## native compiled hashcat
##

obj/%.NATIVE.o:   src/%.c
	$(CC_NATIVE) $(CFLAGS_NATIVE) -c -o $@ $<

hashcat:       src/hashcat.c $(NATIVE_OBJS)
	$(CC_NATIVE) $(CFLAGS_NATIVE)    -o $(BINARY_NATIVE) $^ $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

##
## cross compiled hashcat for binary release version
##

obj/%.LINUX.32.o: src/%.c
	$(CC_LINUX_32) -D_LINUX32 $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.LINUX.64.o: src/%.c
	$(CC_LINUX_64) -D_LINUX64 $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64) -c -o $@ $<

obj/%.WIN.32.o:   src/%.c
	$(CC_WIN_32)   -D_WIN32   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.WIN.64.o:   src/%.c
	$(CC_WIN_64)   -D_WIN64   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64) -c -o $@ $<

hashcat32.bin: src/hashcat.c $(LINUX_32_OBJS)
	$(CC_LINUX_32) -D_LINUX32 $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat64.bin: src/hashcat.c $(LINUX_64_OBJS)
	$(CC_LINUX_64) -D_LINUX64 $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat32.exe: src/hashcat.c $(WIN_32_OBJS)
	$(CC_WIN_32)   -D_WIN32   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -static-libgcc

hashcat64.exe: src/hashcat.c $(WIN_64_OBJS)
	$(CC_WIN_64)   -D_WIN64   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -static-libgcc
