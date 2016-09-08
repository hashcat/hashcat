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
CFLAGS_NATIVE            += -DHAVE_HWMON
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
CFLAGS_CROSS_LINUX       += -DHAVE_HWMON

#CFLAGS_CROSS_WIN         := -D_WIN -DWIN -D__MSVCRT__ -D__USE_MINGW_ANSI_STDIO=1
CFLAGS_CROSS_WIN         :=
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

NATIVE_OBJS              := obj/status.NATIVE.o obj/restore.NATIVE.o obj/bitmap.NATIVE.o obj/opencl.NATIVE.o obj/affinity.NATIVE.o obj/filehandling.NATIVE.o obj/tuningdb.NATIVE.o obj/locking.NATIVE.o obj/folder.NATIVE.o obj/bitops.NATIVE.o obj/convert.NATIVE.o obj/cpu_aes.NATIVE.o obj/cpu_crc32.NATIVE.o obj/cpu_des.NATIVE.o obj/cpu_md5.NATIVE.o obj/cpu_sha1.NATIVE.o obj/cpu_sha256.NATIVE.o obj/data.NATIVE.o obj/ext_OpenCL.NATIVE.o obj/hwmon.NATIVE.o obj/interface.NATIVE.o obj/logfile.NATIVE.o obj/logging.NATIVE.o obj/memory.NATIVE.o obj/mpsp.NATIVE.o obj/rp_cpu.NATIVE.o obj/rp_kernel_on_cpu.NATIVE.o obj/shared.NATIVE.o obj/terminal.NATIVE.o obj/usage.NATIVE.o

ifeq ($(UNAME),Linux)
NATIVE_OBJS              += obj/ext_ADL.NATIVE.o
NATIVE_OBJS              += obj/ext_nvapi.NATIVE.o
NATIVE_OBJS              += obj/ext_nvml.NATIVE.o
NATIVE_OBJS              += obj/ext_xnvctrl.NATIVE.o
endif

LINUX_32_OBJS            := obj/status.LINUX.32.o obj/restore.LINUX.32.o obj/bitmap.LINUX.32.o obj/opencl.LINUX.32.o obj/affinity.LINUX.32.o obj/filehandling.LINUX.32.o obj/tuningdb.LINUX.32.o obj/locking.LINUX.32.o obj/folder.LINUX.32.o obj/bitops.LINUX.32.o obj/convert.LINUX.32.o obj/cpu_aes.LINUX.32.o obj/cpu_crc32.LINUX.32.o obj/cpu_des.LINUX.32.o obj/cpu_md5.LINUX.32.o obj/cpu_sha1.LINUX.32.o obj/cpu_sha256.LINUX.32.o obj/data.LINUX.32.o obj/ext_ADL.LINUX.32.o obj/ext_nvapi.LINUX.32.o obj/ext_nvml.LINUX.32.o obj/ext_OpenCL.LINUX.32.o obj/ext_xnvctrl.LINUX.32.o obj/hwmon.LINUX.32.o obj/interface.LINUX.32.o obj/logfile.LINUX.32.o obj/logging.LINUX.32.o obj/memory.LINUX.32.o obj/mpsp.LINUX.32.o obj/rp_cpu.LINUX.32.o obj/rp_kernel_on_cpu.LINUX.32.o obj/shared.LINUX.32.o obj/terminal.LINUX.32.o obj/usage.LINUX.32.o
LINUX_64_OBJS            := obj/status.LINUX.64.o obj/restore.LINUX.64.o obj/bitmap.LINUX.64.o obj/opencl.LINUX.64.o obj/affinity.LINUX.64.o obj/filehandling.LINUX.64.o obj/tuningdb.LINUX.64.o obj/locking.LINUX.64.o obj/folder.LINUX.64.o obj/bitops.LINUX.64.o obj/convert.LINUX.64.o obj/cpu_aes.LINUX.64.o obj/cpu_crc32.LINUX.64.o obj/cpu_des.LINUX.64.o obj/cpu_md5.LINUX.64.o obj/cpu_sha1.LINUX.64.o obj/cpu_sha256.LINUX.64.o obj/data.LINUX.64.o obj/ext_ADL.LINUX.64.o obj/ext_nvapi.LINUX.64.o obj/ext_nvml.LINUX.64.o obj/ext_OpenCL.LINUX.64.o obj/ext_xnvctrl.LINUX.64.o obj/hwmon.LINUX.64.o obj/interface.LINUX.64.o obj/logfile.LINUX.64.o obj/logging.LINUX.64.o obj/memory.LINUX.64.o obj/mpsp.LINUX.64.o obj/rp_cpu.LINUX.64.o obj/rp_kernel_on_cpu.LINUX.64.o obj/shared.LINUX.64.o obj/terminal.LINUX.64.o obj/usage.LINUX.64.o

# Windows CRT file globbing:

CRT_GLOB_32              :=
CRT_GLOB_64              :=
CRT_GLOB_INCLUDE_FOLDER  := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CRT_GLOB_INCLUDE_FOLDER)/win_file_globbing.mk

WIN_32_OBJS              := obj/status.WIN.32.o obj/restore.WIN.32.o obj/bitmap.WIN.32.o obj/opencl.WIN.32.o obj/affinity.WIN.32.o obj/filehandling.WIN.32.o obj/tuningdb.WIN.32.o obj/locking.WIN.32.o obj/folder.WIN.32.o obj/bitops.WIN.32.o obj/convert.WIN.32.o obj/cpu_aes.WIN.32.o obj/cpu_crc32.WIN.32.o obj/cpu_des.WIN.32.o obj/cpu_md5.WIN.32.o obj/cpu_sha1.WIN.32.o obj/cpu_sha256.WIN.32.o obj/data.WIN.32.o obj/ext_ADL.WIN.32.o obj/ext_nvapi.WIN.32.o obj/ext_nvml.WIN.32.o obj/ext_OpenCL.WIN.32.o obj/ext_xnvctrl.WIN.32.o obj/hwmon.WIN.32.o obj/interface.WIN.32.o obj/logfile.WIN.32.o obj/logging.WIN.32.o obj/memory.WIN.32.o obj/mpsp.WIN.32.o obj/rp_cpu.WIN.32.o obj/rp_kernel_on_cpu.WIN.32.o obj/shared.WIN.32.o obj/terminal.WIN.32.o obj/usage.WIN.32.o $(CRT_GLOB_32)
WIN_64_OBJS              := obj/status.WIN.64.o obj/restore.WIN.64.o obj/bitmap.WIN.64.o obj/opencl.WIN.64.o obj/affinity.WIN.64.o obj/filehandling.WIN.64.o obj/tuningdb.WIN.64.o obj/locking.WIN.64.o obj/folder.WIN.64.o obj/bitops.WIN.64.o obj/convert.WIN.64.o obj/cpu_aes.WIN.64.o obj/cpu_crc32.WIN.64.o obj/cpu_des.WIN.64.o obj/cpu_md5.WIN.64.o obj/cpu_sha1.WIN.64.o obj/cpu_sha256.WIN.64.o obj/data.WIN.64.o obj/ext_ADL.WIN.64.o obj/ext_nvapi.WIN.64.o obj/ext_nvml.WIN.64.o obj/ext_OpenCL.WIN.64.o obj/ext_xnvctrl.WIN.64.o obj/hwmon.WIN.64.o obj/interface.WIN.64.o obj/logfile.WIN.64.o obj/logging.WIN.64.o obj/memory.WIN.64.o obj/mpsp.WIN.64.o obj/rp_cpu.WIN.64.o obj/rp_kernel_on_cpu.WIN.64.o obj/shared.WIN.64.o obj/terminal.WIN.64.o obj/usage.WIN.64.o $(CRT_GLOB_64)

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

hashcat:       src/hashcat.c $(NATIVE_OBJS)
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

hashcat32.bin: src/hashcat.c $(LINUX_32_OBJS)
	$(CC_LINUX_32) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat64.bin: src/hashcat.c $(LINUX_64_OBJS)
	$(CC_LINUX_64) $(CFLAGS_CROSS_LINUX) $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_LINUX) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"

hashcat32.exe: src/hashcat.c $(WIN_32_OBJS)
	$(CC_WIN_32)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_32)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"

hashcat64.exe: src/hashcat.c $(WIN_64_OBJS)
	$(CC_WIN_64)   $(CFLAGS_CROSS_WIN)   $(CFLAGS_CROSS_64)    -o $@ $^ $(LFLAGS_CROSS_WIN)   -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\"
