##
## Authors.....: Jens Steube <jens.steube@gmail.com>
##               Gabriele Gristina <matrix@hashcat.net>
##               magnum <john.magnum@hushmail.com>
##
## License.....: MIT
##

PROG_NAME                := oclHashcat

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

PREFIX                   ?= /usr/local

INSTALL_FOLDER           ?= $(PREFIX)/bin
SHARED_FOLDER            ?= $(PREFIX)/share/$(PROG_NAME)
DOCUMENT_FOLDER          ?= $(PREFIX)/share/doc/$(PROG_NAME)

##
## Dependencies, cross compilation only
##

OPENCL_HEADERS_KHRONOS   := deps/OpenCL-Headers

##

WITH_ADL                 := 1
WITH_NVML                := 1
WITH_NVAPI               := 1

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
VERSION_TAG              := $(shell git describe --tags --dirty=+ | cut -d- -f1)
VERSION_SUM              := $(shell git describe --tags --dirty=+ | cut -d- -f3)

##
## Compiler flags
##

CFLAGS                   := -pipe -W -Wall -std=c99 -Iinclude/

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

BINARY_NATIVE            := $(PROG_NAME).app

CFLAGS_NATIVE            := -D_POSIX -DOSX
CFLAGS_NATIVE            += $(CFLAGS)

LFLAGS_NATIVE            := -lpthread

WITH_ADL                 := 0
WITH_NVML                := 0
endif # darwin

ifeq ($(UNAME),Linux)
CFLAGS_NATIVE            := -D_POSIX -DLINUX

ifndef DEBUG
CFLAGS_NATIVE            += -s
endif

CFLAGS_NATIVE            += $(CFLAGS)

LFLAGS_NATIVE            := -lpthread -ldl

ifneq (,$(filter 1,$(WITH_ADL) $(WITH_NVML)))
CFLAGS_NATIVE            += -DHAVE_HWMON

ifeq ($(WITH_ADL),1)
CFLAGS_NATIVE            += -DHAVE_ADL
endif

ifeq ($(WITH_NVML),1)
CFLAGS_NATIVE            += -DHAVE_NVML
endif
endif

endif # linux

##
## Cross compilation target
##

CFLAGS_CROSS_LINUX       := -D_POSIX -DLINUX

ifndef DEBUG
CFLAGS_CROSS_LINUX       += -s
endif

CFLAGS_CROSS_LINUX       += $(CFLAGS)
CFLAGS_CROSS_LINUX       += -I$(OPENCL_HEADERS_KHRONOS)/

ifneq (,$(filter 1,$(WITH_ADL) $(WITH_NVML)))
CFLAGS_CROSS_LINUX       += -DHAVE_HWMON

ifeq ($(WITH_ADL),1)
CFLAGS_CROSS_LINUX       += -DHAVE_ADL
endif

ifeq ($(WITH_NVML),1)
CFLAGS_CROSS_LINUX       += -DHAVE_NVML
endif
endif

CFLAGS_CROSS_WIN         := -D_WIN   -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1

ifndef DEBUG
CFLAGS_CROSS_WIN         += -s
endif

CFLAGS_CROSS_WIN         += $(filter-out -fsanitize=address,$(CFLAGS))
CFLAGS_CROSS_WIN         += -I$(OPENCL_HEADERS_KHRONOS)/

ifneq (,$(filter 1,$(WITH_ADL) $(WITH_NVAPI)))
CFLAGS_CROSS_WIN         += -DHAVE_HWMON

ifeq ($(WITH_ADL),1)
CFLAGS_CROSS_WIN         += -DHAVE_ADL
endif

ifeq ($(WITH_NVAPI),1)
CFLAGS_CROSS_WIN         += -DHAVE_NVAPI
endif
endif

CFLAGS_CROSS_32          := -m32
CFLAGS_CROSS_64          := -m64

LFLAGS_CROSS_LINUX       := -lpthread -ldl
LFLAGS_CROSS_WIN         := -lpsapi

##
## Objects
##

NATIVE_OBJS              := obj/ext_OpenCL.NATIVE.o obj/shared.NATIVE.o obj/rp_kernel_on_cpu.NATIVE.o

ifneq (,$(filter 1,$(WITH_ADL) $(WITH_NVML)))
ifeq ($(WITH_ADL),1)
NATIVE_OBJS              += obj/ext_ADL.NATIVE.o
endif

ifeq ($(WITH_NVML),1)
NATIVE_OBJS              += obj/ext_nvml.NATIVE.o
endif
endif

LINUX_32_OBJS            := obj/ext_OpenCL.LINUX.32.o obj/shared.LINUX.32.o obj/rp_kernel_on_cpu.LINUX.32.o
LINUX_64_OBJS            := obj/ext_OpenCL.LINUX.64.o obj/shared.LINUX.64.o obj/rp_kernel_on_cpu.LINUX.64.o

WIN_32_OBJS              := obj/ext_OpenCL.WIN.32.o obj/shared.WIN.32.o obj/rp_kernel_on_cpu.WIN.32.o
WIN_64_OBJS              := obj/ext_OpenCL.WIN.64.o obj/shared.WIN.64.o obj/rp_kernel_on_cpu.WIN.64.o

ifeq ($(WITH_ADL),1)
LINUX_32_OBJS            += obj/ext_ADL.LINUX.32.o
LINUX_64_OBJS            += obj/ext_ADL.LINUX.64.o

WIN_32_OBJS              += obj/ext_ADL.WIN.32.o
WIN_64_OBJS              += obj/ext_ADL.WIN.64.o
endif

ifeq ($(WITH_NVML),1)
LINUX_32_OBJS            += obj/ext_nvml.LINUX.32.o
LINUX_64_OBJS            += obj/ext_nvml.LINUX.64.o
endif

ifeq ($(WITH_NVAPI),1)
WIN_32_OBJS              += obj/ext_nvapi.WIN.32.o
WIN_64_OBJS              += obj/ext_nvapi.WIN.64.o
endif

##
## Targets: Global
##

native: oclHashcat

binaries: linux32 linux64 win32 win64

clean:
	$(RM) -f obj/*.o *.bin *.exe *.app *.restore *.out *.pot *.dictstat *.log oclHashcat core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf *.dSYM
	$(RM) -rf kernels

linux32: oclHashcat32.bin
linux64: oclHashcat64.bin

win32: oclHashcat32.exe
win64: oclHashcat64.exe

##
## Targets: Linux install
## How to make /usr/bin/install doing recursive??
##

install: native
	$(INSTALL) -m 755 -d                            $(DOCUMENT_FOLDER)
	$(CP) -a docs/*                                 $(DOCUMENT_FOLDER)/
	$(CP) -a example*.sh                            $(DOCUMENT_FOLDER)/
	$(CP) -a example*.hash                          $(DOCUMENT_FOLDER)/
	$(INSTALL) -m 644 example.dict                  $(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 -d                            $(DOCUMENT_FOLDER)/extra
	$(CP) -a extra/*                                $(DOCUMENT_FOLDER)/extra/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/charsets
	$(CP) -a charsets/*                             $(SHARED_FOLDER)/charsets/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/masks
	$(CP) -a masks/*                                $(SHARED_FOLDER)/masks/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/include
	$(INSTALL) -m 644 include/constants.h           $(SHARED_FOLDER)/include/
	$(INSTALL) -m 644 include/kernel_functions.c    $(SHARED_FOLDER)/include/
	$(INSTALL) -m 644 include/kernel_vendor.h       $(SHARED_FOLDER)/include/
	$(INSTALL) -m 644 include/rp_kernel.h           $(SHARED_FOLDER)/include/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/OpenCL
	$(CP) -a OpenCL/*                               $(SHARED_FOLDER)/OpenCL/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/rules
	$(CP) -a rules/*                                $(SHARED_FOLDER)/rules/
	$(INSTALL) -m 644 hashcat.hcstat                $(SHARED_FOLDER)/
	$(INSTALL) -m 755 $(BINARY_NATIVE)              $(INSTALL_FOLDER)/

uninstall:
	$(RM) -f  $(INSTALL_FOLDER)/$(BINARY_NATIVE)
	$(RM) -rf $(SHARED_FOLDER)
	$(RM) -rf $(DOCUMENT_FOLDER)

##
## native compiled oclHashcat
##

obj/%.NATIVE.o:   src/%.c
	$(CC_NATIVE) $(CFLAGS_NATIVE) -c -o $@ $<

oclHashcat:       src/oclHashcat.c $(NATIVE_OBJS)
	$(CC_NATIVE) $(CFLAGS_NATIVE)    -o $(BINARY_NATIVE) $^ $(LFLAGS_NATIVE) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_SUM=\"$(VERSION_SUM)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

##
## cross compiled oclHashcat for binary release version
##

obj/%.LINUX.32.o: src/%.c
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.LINUX.64.o: src/%.c
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64) -c -o $@ $<

obj/%.WIN.32.o:   src/%.c
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.WIN.64.o:   src/%.c
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64) -c -o $@ $<

oclHashcat32.bin: src/oclHashcat.c $(LINUX_32_OBJS)
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_SUM=\"$(VERSION_SUM)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat64.bin: src/oclHashcat.c $(LINUX_64_OBJS)
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_SUM=\"$(VERSION_SUM)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat32.exe: src/oclHashcat.c $(WIN_32_OBJS)
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_SUM=\"$(VERSION_SUM)\" -static-libgcc

oclHashcat64.exe: src/oclHashcat.c $(WIN_64_OBJS)
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_SUM=\"$(VERSION_SUM)\" -static-libgcc
