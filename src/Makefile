##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

##
## Makefile flags
##

MAKEFLAGS += -l -j -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS += -j 1
endif

##
## Installation paths (Linux only)
##

PREFIX                   ?= /usr/local

INSTALL_FOLDER           ?= $(PREFIX)/bin
SHARED_FOLDER            ?= $(PREFIX)/share/oclHashcat
DOCUMENT_FOLDER          ?= $(PREFIX)/share/doc/oclHashcat

##
## Main SDK
##

AMDAPP                   := deps/amd-app-sdk
AMDAPPLIBPATH32          := $(AMDAPP)/lib/x86
AMDAPPLIBPATH64          := $(AMDAPP)/lib/x86_64

ADL                      := deps/adl-sdk
GDK                      := deps/nvidia-gdk
NVAPI                    := deps/R352-developer

##
## Library paths
##

OCL                      := $(AMDAPP)
OCLLIBPATH32             := $(AMDAPPLIBPATH32)
OCLLIBPATH64             := $(AMDAPPLIBPATH64)

NVML                     := $(GDK)/usr/include/nvidia/gdk

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

DLL_WIN_32               := i686-w64-mingw32-dlltool
DLL_WIN_64               := x86_64-w64-mingw32-dlltool

##
## Misc stuff
##

NOW                      := $(shell perl -e 'print time')

##
## Compiler flags
##

CFLAGS                   := -O2 -s -pipe -W -Wall -Iinclude/ -std=c99
#CFLAGS                   := -g -pipe -W -Wall -Iinclude/ -std=c99

CFLAGS_32                := -m32
CFLAGS_64                := -m64

CFLAGS_LINUX             := -D_POSIX -DLINUX
CFLAGS_WIN               := -D_WIN   -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1

CFLAGS_LINUX             += -I$(OCL)/include/ -I$(ADL)/include/ -I$(NVML)/
CFLAGS_WIN               += -I$(OCL)/include/ -I$(ADL)/include/ -I$(NVAPI)/

LFLAGS_LINUX             := -lpthread -lOpenCL -ldl
LFLAGS_WIN               := -lpsapi

CFLAGS_NATIVE            := $(CFLAGS_LINUX)
LFLAGS_NATIVE            := $(LFLAGS_LINUX)

##
## Targets: Global
##

native: oclHashcat

binaries: linux32 linux64 win32 win64

clean:
	$(RM) -f obj/*.o lib/*.a ./*.bin ./*.exe ./*.app *.restore *.out *.pot *.dictstat *.log oclHashcat core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles

linux32:        oclHashcat32.bin
linux64:        oclHashcat64.bin

win32:          oclHashcat32.exe
win64:          oclHashcat64.exe

##
## Targets: Linux install
## How to make /usr/bin/install doing recursive??
##

install: native
	$(INSTALL) -m 755 -d                            $(DOCUMENT_FOLDER)
	$(CP) -a docs/*                                 $(DOCUMENT_FOLDER)/
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
	$(INSTALL) -m 644 include/rp_gpu.h              $(SHARED_FOLDER)/include/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/OpenCL
	$(CP) -a OpenCL/*                               $(SHARED_FOLDER)/OpenCL/
	$(INSTALL) -m 755 -d                            $(SHARED_FOLDER)/rules
	$(CP) -a rules/*                                $(SHARED_FOLDER)/rules/
	$(INSTALL) -m 644 hashcat.hcstat                $(SHARED_FOLDER)/
	$(INSTALL) -m 755 oclHashcat                    $(INSTALL_FOLDER)/

uninstall:
	$(RM) -f  $(INSTALL_FOLDER)/oclHashcat
	$(RM) -rf $(SHARED_FOLDER)
	$(RM) -rf $(DOCUMENT_FOLDER)

##
## Targets: Libraries
##

lib/libOpenCL.a:
	${DLL_WIN_32} -A -k -l lib/libOpenCL.a   -d lib/OpenCL.def

lib/libOpenCL64.a:
	${DLL_WIN_64} -A -k -l lib/libOpenCL64.a -d lib/OpenCL64.def

##
## native compiled oclHashcat
##

obj/%.oclHashcat.NATIVE.o: src/%.c
	$(CC_NATIVE) $(CFLAGS) $(CFLAGS_NATIVE) -c -o $@ $<

oclHashcat: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.NATIVE.o obj/ext_nvml.oclHashcat.NATIVE.o obj/ext_ADL.oclHashcat.NATIVE.o obj/shared.oclHashcat.NATIVE.o obj/rp_gpu_on_cpu.oclHashcat.NATIVE.o
	$(CC_NATIVE) $(CFLAGS) $(CFLAGS_NATIVE)    -o $@ $^ $(LFLAGS_NATIVE) -DCOMPTIME=$(NOW) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

##
## cross compiled oclHashcat for release
##

obj/%.oclHashcat.LINUX.32.o: src/%.c
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32) -c -o $@ $<

obj/%.oclHashcat.LINUX.64.o: src/%.c
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64) -c -o $@ $<

obj/%.oclHashcat.WIN.32.o: src/%.c
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32) -c -o $@ $<

obj/%.oclHashcat.WIN.64.o: src/%.c
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64) -c -o $@ $<

oclHashcat32.bin: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.32.o obj/ext_nvml.oclHashcat.LINUX.32.o obj/ext_ADL.oclHashcat.LINUX.32.o    obj/shared.oclHashcat.LINUX.32.o  obj/rp_gpu_on_cpu.oclHashcat.LINUX.32.o
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32)    -o $@ $^ -L$(OCLLIBPATH32)  $(LFLAGS_LINUX) -DCOMPTIME=$(NOW) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat64.bin: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.64.o obj/ext_nvml.oclHashcat.LINUX.64.o obj/ext_ADL.oclHashcat.LINUX.64.o    obj/shared.oclHashcat.LINUX.64.o  obj/rp_gpu_on_cpu.oclHashcat.LINUX.64.o
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64)    -o $@ $^ -L$(OCLLIBPATH64)  $(LFLAGS_LINUX) -DCOMPTIME=$(NOW) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat32.exe: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.32.o   obj/ext_nvapi.oclHashcat.WIN.32.o  obj/ext_ADL.oclHashcat.WIN.32.o      obj/shared.oclHashcat.WIN.32.o    obj/rp_gpu_on_cpu.oclHashcat.WIN.32.o      lib/libOpenCL.a   /usr/i686-w64-mingw32/lib/CRT_glob.o   $(NVAPI)/x86/nvapi.lib
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32)    -o $@ $^ -L$(OCLLIBPATH32)  $(LFLAGS_WIN)   -DCOMPTIME=$(NOW) -static-libgcc

oclHashcat64.exe: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.64.o   obj/ext_nvapi.oclHashcat.WIN.64.o  obj/ext_ADL.oclHashcat.WIN.64.o      obj/shared.oclHashcat.WIN.64.o    obj/rp_gpu_on_cpu.oclHashcat.WIN.64.o      lib/libOpenCL64.a /usr/x86_64-w64-mingw32/lib/CRT_glob.o $(NVAPI)/amd64/nvapi64.lib
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64)    -o $@ $^ -L$(OCLLIBPATH64)  $(LFLAGS_WIN)   -DCOMPTIME=$(NOW) -static-libgcc
