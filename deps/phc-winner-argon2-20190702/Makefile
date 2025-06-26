#
# Argon2 reference source code package - reference C implementations
#
# Copyright 2015
# Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
#
# You may use this work under the terms of a Creative Commons CC0 1.0
# License/Waiver or the Apache Public License 2.0, at your option. The terms of
# these licenses can be found at:
#
# - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
# - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
#
# You should have received a copy of both of these licenses along with this
# software. If not, they may be obtained at the above URLs.
#

RUN = argon2
BENCH = bench
GENKAT = genkat
ARGON2_VERSION ?= ZERO

# installation parameters for staging area and final installation path
# Note; if Linux and not Debian/Ubuntu version also add lib override to make command-line
#       for RedHat/Fedora, add: LIBRARY_REL=lib64
DESTDIR ?=
PREFIX ?= /usr

# Increment on an ABI breaking change
ABI_VERSION = 1

DIST = phc-winner-argon2

SRC = src/argon2.c src/core.c src/blake2/blake2b.c src/thread.c src/encoding.c
SRC_RUN = src/run.c
SRC_BENCH = src/bench.c
SRC_GENKAT = src/genkat.c
OBJ = $(SRC:.c=.o)

CFLAGS += -std=c89 -O3 -Wall -g -Iinclude -Isrc

ifeq ($(NO_THREADS), 1)
CFLAGS += -DARGON2_NO_THREADS
else
CFLAGS += -pthread
endif

CI_CFLAGS := $(CFLAGS) -Werror=declaration-after-statement -D_FORTIFY_SOURCE=2 \
				-Wextra -Wno-type-limits -Werror -coverage -DTEST_LARGE_RAM

OPTTARGET ?= native
OPTTEST := $(shell $(CC) -Iinclude -Isrc -march=$(OPTTARGET) src/opt.c -c \
			-o /dev/null 2>/dev/null; echo $$?)
# Detect compatible platform
ifneq ($(OPTTEST), 0)
$(info Building without optimizations)
	SRC += src/ref.c
else
$(info Building with optimizations for $(OPTTARGET))
	CFLAGS += -march=$(OPTTARGET)
	SRC += src/opt.c
endif

BUILD_PATH := $(shell pwd)
KERNEL_NAME := $(shell uname -s)
MACHINE_NAME := $(shell uname -m)

LIB_NAME = argon2
PC_NAME = lib$(LIB_NAME).pc
PC_SRC = $(PC_NAME).in

ifeq ($(KERNEL_NAME), Linux)
	LIB_EXT := so.$(ABI_VERSION)
	LIB_CFLAGS := -shared -fPIC -fvisibility=hidden -DA2_VISCTL=1
	SO_LDFLAGS := -Wl,-soname,lib$(LIB_NAME).$(LIB_EXT)
	LINKED_LIB_EXT := so
	PC_EXTRA_LIBS ?= -lrt -ldl
endif
ifeq ($(KERNEL_NAME), $(filter $(KERNEL_NAME),DragonFly FreeBSD NetBSD OpenBSD))
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	PC_EXTRA_LIBS ?=
endif
ifeq ($(KERNEL_NAME), Darwin)
	LIB_EXT := $(ABI_VERSION).dylib
	LIB_CFLAGS := -dynamiclib -install_name @rpath/lib$(LIB_NAME).$(LIB_EXT)
	LINKED_LIB_EXT := dylib
	PC_EXTRA_LIBS ?=
endif
ifeq ($(findstring CYGWIN, $(KERNEL_NAME)), CYGWIN)
	LIB_EXT := dll
	LIB_CFLAGS := -shared -Wl,--out-implib,lib$(LIB_NAME).$(LIB_EXT).a
	PC_EXTRA_LIBS ?=
endif
ifeq ($(findstring MINGW, $(KERNEL_NAME)), MINGW)
	LIB_EXT := dll
	LIB_CFLAGS := -shared -Wl,--out-implib,lib$(LIB_NAME).$(LIB_EXT).a
	PC_EXTRA_LIBS ?=
endif
ifeq ($(findstring MSYS, $(KERNEL_NAME)), MSYS)
	LIB_EXT := dll
	LIB_CFLAGS := -shared -Wl,--out-implib,lib$(LIB_NAME).$(LIB_EXT).a
	PC_EXTRA_LIBS ?=
endif
ifeq ($(KERNEL_NAME), SunOS)
	CC := gcc
	CFLAGS += -D_REENTRANT
	LIB_EXT := so
	LIB_CFLAGS := -shared -fPIC
	PC_EXTRA_LIBS ?=
endif

ifeq ($(KERNEL_NAME), Linux)
ifeq ($(CC), clang)
	CI_CFLAGS += -fsanitize=address -fsanitize=undefined
endif
endif

LIB_SH := lib$(LIB_NAME).$(LIB_EXT)
LIB_ST := lib$(LIB_NAME).a

ifdef LINKED_LIB_EXT
LINKED_LIB_SH := lib$(LIB_NAME).$(LINKED_LIB_EXT)
endif


LIBRARIES = $(LIB_SH) $(LIB_ST)
HEADERS = include/argon2.h

INSTALL = install

# relative paths for different OS
ifeq ($(KERNEL_NAME), $(filter $(KERNEL_NAME),DragonFly FreeBSD))

# default for FreeBSD
BINARY_REL ?= bin
INCLUDE_REL ?= include
LIBRARY_REL ?= lib
PKGCONFIG_REL ?= libdata

else ifeq ($(KERNEL_NAME)-$(MACHINE_NAME), Linux-x86_64)

# default for Debian/Ubuntu x86_64
BINARY_REL ?= bin
INCLUDE_REL ?= include
LIBRARY_REL ?= lib/x86_64-linux-gnu
PKGCONFIG_REL ?= $(LIBRARY_REL)

else

# NetBSD, ... and Linux64/Linux32 variants that use plain lib directory
BINARY_REL ?= bin
INCLUDE_REL ?= include
LIBRARY_REL ?= lib
PKGCONFIG_REL ?= $(LIBRARY_REL)

endif

# absolute paths to staging area
INST_INCLUDE = $(DESTDIR)$(PREFIX)/$(INCLUDE_REL)
INST_LIBRARY = $(DESTDIR)$(PREFIX)/$(LIBRARY_REL)
INST_BINARY = $(DESTDIR)$(PREFIX)/$(BINARY_REL)
INST_PKGCONFIG = $(DESTDIR)$(PREFIX)/$(PKGCONFIG_REL)/pkgconfig

# main target
.PHONY: all
all: $(RUN) libs

.PHONY: libs
libs: $(LIBRARIES) $(PC_NAME)

$(RUN):	        $(SRC) $(SRC_RUN)
		$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(BENCH):       $(SRC) $(SRC_BENCH)
		$(CC) $(CFLAGS) $^ -o $@

$(GENKAT):      $(SRC) $(SRC_GENKAT)
		$(CC) $(CFLAGS) $^ -o $@ -DGENKAT

$(LIB_SH): 	$(SRC)
		$(CC) $(CFLAGS) $(LIB_CFLAGS) $(LDFLAGS) $(SO_LDFLAGS) $^ -o $@

$(LIB_ST): 	$(OBJ)
		ar rcs $@ $^

.PHONY: clean
clean:
		rm -f '$(RUN)' '$(BENCH)' '$(GENKAT)'
		rm -f '$(LIB_SH)' '$(LIB_ST)' kat-argon2* '$(PC_NAME)'
		rm -f testcase
		rm -rf *.dSYM
		cd src/ && rm -f *.o
		cd src/blake2/ && rm -f *.o
		cd kats/ &&  rm -f kat-* diff* run_* make_*


# all substitutions to pc template
SED_COMMANDS  = /^\#\#.*$$/d;
SED_COMMANDS += s\#@PREFIX@\#$(PREFIX)\#g;
SED_COMMANDS += s\#@EXTRA_LIBS@\#$(PC_EXTRA_LIBS)\#g;
SED_COMMANDS += s\#@UPSTREAM_VER@\#$(ARGON2_VERSION)\#g;
SED_COMMANDS += s\#@HOST_MULTIARCH@\#$(LIBRARY_REL)\#g;
SED_COMMANDS += s\#@INCLUDE@\#$(INCLUDE_REL)\#g;

# substitute PREFIX and PC_EXTRA_LIBS into pkgconfig pc file
$(PC_NAME): $(PC_SRC)
		sed '$(SED_COMMANDS)' < '$(PC_SRC)' > '$@'


.PHONY: dist
dist:
		cd ..; \
		tar -c --exclude='.??*' -z -f $(DIST)-`date "+%Y%m%d"`.tgz $(DIST)/*

.PHONY: test
test:           $(SRC) src/test.c
		$(CC) $(CFLAGS)  -Wextra -Wno-type-limits $^ -o testcase
		@sh kats/test.sh
		./testcase

.PHONY: testci
testci:         $(SRC) src/test.c
		$(CC) $(CI_CFLAGS) $^ -o testcase
		@sh kats/test.sh
		./testcase


.PHONY: format
format:
		clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4}" \
			-i include/*.h src/*.c src/*.h src/blake2/*.c src/blake2/*.h

.PHONY: install
install: $(RUN) libs
	$(INSTALL) -d $(INST_INCLUDE)
	$(INSTALL) -m 0644 $(HEADERS) $(INST_INCLUDE)
	$(INSTALL) -d $(INST_LIBRARY)
	$(INSTALL) -m 0644 $(LIBRARIES) $(INST_LIBRARY)
ifdef LINKED_LIB_SH
	cd $(INST_LIBRARY) && ln -s $(notdir $(LIB_SH) $(LINKED_LIB_SH))
endif
	$(INSTALL) -d $(INST_BINARY)
	$(INSTALL) $(RUN) $(INST_BINARY)
	$(INSTALL) -d $(INST_PKGCONFIG)
	$(INSTALL) -m 0644 $(PC_NAME) $(INST_PKGCONFIG)

.PHONY: uninstall
uninstall:
	cd $(INST_INCLUDE) && rm -f $(notdir $(HEADERS))
	cd $(INST_LIBRARY) && rm -f $(notdir $(LIBRARIES) $(LINKED_LIB_SH))
	cd $(INST_BINARY) && rm -f $(notdir $(RUN))
	cd $(INST_PKG_CONFIG) && rm -f $(notdir $(PC_NAME))
