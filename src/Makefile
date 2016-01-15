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
## Depencies
##

ADL                      := deps/adl-sdk
GDK                      := deps/nvidia-gdk
NVAPI                    := deps/R352-developer

##
## Depencies, cross compilation only
##

OPENCL_HEADERS_KHRONOS   := deps/OpenCL-Headers

##
## Library paths
##

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

NOW                      := $(shell date +%s)

##
## Compiler flags
##

CFLAGS                   := -O2 -s -pipe -W -Wall -std=c99 -Iinclude/
#CFLAGS                   := -g -ggdb -pipe -W -Wall -std=c99 -Iinclude/ -fsanitize=undefined -fno-omit-frame-pointer

##
## Native compilation target
##

CFLAGS_NATIVE            := -D_POSIX -DLINUX
CFLAGS_NATIVE            += $(CFLAGS)
CFLAGS_NATIVE            += -I$(ADL)/include/
CFLAGS_NATIVE            += -I$(NVML)/

LFLAGS_NATIVE            := -lpthread -lOpenCL -ldl

##
## Cross compilation target
##

CFLAGS_CROSS_LINUX       := -D_POSIX -DLINUX
CFLAGS_CROSS_LINUX       += $(CFLAGS)
CFLAGS_CROSS_LINUX       += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_LINUX       += -I$(ADL)/include/
CFLAGS_CROSS_LINUX       += -I$(NVML)/

CFLAGS_CROSS_WIN         := -D_WIN   -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1
CFLAGS_CROSS_WIN         += $(CFLAGS)
CFLAGS_CROSS_WIN         += -I$(OPENCL_HEADERS_KHRONOS)/
CFLAGS_CROSS_WIN         += -I$(ADL)/include/
CFLAGS_CROSS_WIN         += -I$(NVAPI)/

CFLAGS_CROSS_32          := -m32
CFLAGS_CROSS_64          := -m64

LFLAGS_CROSS_LINUX       := -lpthread -lOpenCL -ldl
LFLAGS_CROSS_WIN         := -lpsapi

##
## Targets: Global
##

native: oclHashcat

binaries: linux32 linux64 win32 win64

clean:
	$(RM) -f obj/*.o lib/*.a ./*.bin ./*.exe ./*.app *.restore *.out *.pot *.dictstat *.log oclHashcat core
	$(RM) -rf *.induct
	$(RM) -rf *.outfiles
	$(RM) -rf kernels

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
	$(INSTALL) -m 644 include/rp_kernel.h              $(SHARED_FOLDER)/include/
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
	$(CC_NATIVE) $(CFLAGS_NATIVE) -c -o $@ $<

oclHashcat: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.NATIVE.o obj/ext_nvml.oclHashcat.NATIVE.o obj/ext_ADL.oclHashcat.NATIVE.o obj/shared.oclHashcat.NATIVE.o obj/rp_kernel_on_cpu.oclHashcat.NATIVE.o
	$(CC_NATIVE) $(CFLAGS_NATIVE)    -o $@ $^ $(LFLAGS_NATIVE) -DCOMPTIME=$(NOW) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

##
## cross compiled oclHashcat for binary release version
##

obj/%.oclHashcat.LINUX.32.o: src/%.c
	$(CC_LINUX_32) $(CFLAGS_CROSS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.oclHashcat.LINUX.64.o: src/%.c
	$(CC_LINUX_64) $(CFLAGS_CROSS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64) -c -o $@ $<

obj/%.oclHashcat.WIN.32.o: src/%.c
	$(CC_WIN_32)   $(CFLAGS_CROSS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32) -c -o $@ $<

obj/%.oclHashcat.WIN.64.o: src/%.c
	$(CC_WIN_64)   $(CFLAGS_CROSS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64) -c -o $@ $<

oclHashcat32.bin: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.32.o obj/ext_nvml.oclHashcat.LINUX.32.o obj/ext_ADL.oclHashcat.LINUX.32.o    obj/shared.oclHashcat.LINUX.32.o  obj/rp_kernel_on_cpu.oclHashcat.LINUX.32.o
	$(CC_LINUX_32) $(CFLAGS_CROSS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(NOW) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat64.bin: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.LINUX.64.o obj/ext_nvml.oclHashcat.LINUX.64.o obj/ext_ADL.oclHashcat.LINUX.64.o    obj/shared.oclHashcat.LINUX.64.o  obj/rp_kernel_on_cpu.oclHashcat.LINUX.64.o
	$(CC_LINUX_64) $(CFLAGS_CROSS) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(NOW) -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

oclHashcat32.exe: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.32.o   obj/ext_nvapi.oclHashcat.WIN.32.o  obj/ext_ADL.oclHashcat.WIN.32.o      obj/shared.oclHashcat.WIN.32.o    obj/rp_kernel_on_cpu.oclHashcat.WIN.32.o      lib/libOpenCL.a   /usr/i686-w64-mingw32/lib/CRT_glob.o   $(NVAPI)/x86/nvapi.lib
	$(CC_WIN_32)   $(CFLAGS_CROSS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(NOW) -static-libgcc

oclHashcat64.exe: src/oclHashcat.c obj/ext_OpenCL.oclHashcat.WIN.64.o   obj/ext_nvapi.oclHashcat.WIN.64.o  obj/ext_ADL.oclHashcat.WIN.64.o      obj/shared.oclHashcat.WIN.64.o    obj/rp_kernel_on_cpu.oclHashcat.WIN.64.o      lib/libOpenCL64.a /usr/x86_64-w64-mingw32/lib/CRT_glob.o $(NVAPI)/amd64/nvapi64.lib
	$(CC_WIN_64)   $(CFLAGS_CROSS) $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(NOW) -static-libgcc
