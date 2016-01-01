##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

##
## Detect number of processors
##

NPROCS   := $(shell grep -c ^processor /proc/cpuinfo)
OS       := $(shell uname)

##
## Makefile flags
##

MAKEFLAGS += -l -j $(NPROCS) -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS += -j 1
endif

##
## Installation paths (Linux only)
##

INSTALL_FOLDER           ?= /opt/test/usr/bin
SHARED_FOLDER            ?= /opt/test/usr/share/oclHashcat
DOCUMENT_FOLDER          ?= /opt/test/usr/share/doc/oclHashcat

#INSTALL_FOLDER           ?= /usr/bin
#SHARED_FOLDER            ?= /usr/share/oclHashcat
#DOCUMENT_FOLDER          ?= /usr/share/doc/oclHashcat

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

CLCOMPILE_PATH           := tools/clcompile
RULES_OPTIMIZE_PATH      := tools/rules_optimize

##
## Compiler paths
##

CC_LINUX_32              := gcc
CC_LINUX_64              := gcc

CC_WIN_32                := i686-w64-mingw32-gcc
CC_WIN_64                := x86_64-w64-mingw32-gcc

DLL_WIN_32               := i686-w64-mingw32-dlltool
DLL_WIN_64               := x86_64-w64-mingw32-dlltool

CLCOMPILE                := $(CLCOMPILE_PATH)/clcompile.bin

BIN                      := .

INSTALL                  := install
CP                       := cp

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

##
## Targets: Global
##

all: binaries_all

binaries_all: linux32 linux64 win32 win64 rules_optimize

release: binaries

linux: linux32 linux64 rules_optimize

windows: win32 win64 rules_optimize

clean: clean_bin

clean_all: clean_bin clean_clcompile

clean_bin:
	rm -f obj/*.o lib/*.a $(BIN)/*.bin $(BIN)/*.exe $(BIN)/*.app *.restore *.out *.pot *.dictstat *.log
	rm -rf *Hashcat.induct
	rm -rf *Hashcat.outfiles
	$(MAKE) -C $(RULES_OPTIMIZE_PATH) clean

clean_clcompile:
	rm -f ${CLCOMPILE_PATH}/clcompile.bin

${CLCOMPILE}: ${CLCOMPILE_PATH}/clcompile.c
	$(CC_LINUX_64) $(CFLAGS) -o $@ -I$(CFLAGS_LINUX) $< -L$(OCLLIBPATH64) $(LFLAGS_LINUX)

rules_optimize:
	$(MAKE) -C $(RULES_OPTIMIZE_PATH)

linux32:        oclHashcat32.bin
linux64:        oclHashcat64.bin

win32:          oclHashcat32.exe
win64:          oclHashcat64.exe

##
## Targets: Linux install
## We need some better native compilation logic here, fixing it to 64 bit for now and AMD kernels
## How to make /usr/bin/install doing recursive??
##

install: linux64 amd_all
	$(INSTALL) -m 755 -d                     $(DOCUMENT_FOLDER)
	$(CP) -a docs/*                          $(DOCUMENT_FOLDER)/
	$(INSTALL) -m 755 -d                     $(DOCUMENT_FOLDER)/extra
	$(CP) -a extra/*                         $(DOCUMENT_FOLDER)/extra/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/charsets
	$(CP) -a charsets/*                      $(SHARED_FOLDER)/charsets/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/masks
	$(CP) -a masks/*                         $(SHARED_FOLDER)/masks/
	$(INSTALL) -m 755 -d                     $(SHARED_FOLDER)/rules
	$(CP) -a rules/*                         $(SHARED_FOLDER)/rules/
	$(INSTALL) -m 755    -T hashcat.hcstat   $(SHARED_FOLDER)/hashcat.hcstat
	$(INSTALL) -m 755 -s -T oclHashcat64.bin $(INSTALL_FOLDER)/oclHashcat


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
## oclHashcat
##

obj/%.oclHashcat.LINUX.32.o:  src/%.c
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32) -c -o $@ $<

obj/%.oclHashcat.LINUX.64.o:  src/%.c
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64) -c -o $@ $<

obj/%.oclHashcat.WIN.32.o:    src/%.c
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32) -c -o $@ $<

obj/%.oclHashcat.WIN.64.o:    src/%.c
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64) -c -o $@ $<

oclHashcat32.bin:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.32.o obj/ext_nvml.oclHashcat.LINUX.32.o obj/ext_ADL.oclHashcat.LINUX.32.o    obj/shared.oclHashcat.LINUX.32.o  obj/rp_gpu_on_cpu.oclHashcat.LINUX.32.o
	$(CC_LINUX_32) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_32)    -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH32)  $(LFLAGS_LINUX) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat64.bin:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.64.o obj/ext_nvml.oclHashcat.LINUX.64.o obj/ext_ADL.oclHashcat.LINUX.64.o    obj/shared.oclHashcat.LINUX.64.o  obj/rp_gpu_on_cpu.oclHashcat.LINUX.64.o
	$(CC_LINUX_64) $(CFLAGS) $(CFLAGS_LINUX) $(CFLAGS_64)    -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH64)  $(LFLAGS_LINUX) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat32.exe:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.32.o   obj/ext_nvapi.oclHashcat.WIN.32.o  obj/ext_ADL.oclHashcat.WIN.32.o      obj/shared.oclHashcat.WIN.32.o    obj/rp_gpu_on_cpu.oclHashcat.WIN.32.o      lib/libOpenCL.a   /usr/i686-w64-mingw32/lib/CRT_glob.o   $(NVAPI)/x86/nvapi.lib
	$(CC_WIN_32)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_32)    -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH32)  $(LFLAGS_WIN) -static-libgcc

oclHashcat64.exe:  src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.64.o   obj/ext_nvapi.oclHashcat.WIN.64.o  obj/ext_ADL.oclHashcat.WIN.64.o      obj/shared.oclHashcat.WIN.64.o    obj/rp_gpu_on_cpu.oclHashcat.WIN.64.o      lib/libOpenCL64.a /usr/x86_64-w64-mingw32/lib/CRT_glob.o $(NVAPI)/amd64/nvapi64.lib
	$(CC_WIN_64)   $(CFLAGS) $(CFLAGS_WIN)   $(CFLAGS_64)    -o $@ -DCOMPTIME=$(NOW) $^ -L$(OCLLIBPATH64)  $(LFLAGS_WIN) -static-libgcc
