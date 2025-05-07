# ################################################################
# xxHash Makefile
# Copyright (C) 2012-2024 Yann Collet
#
# GPL v2 License
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You can contact the author at:
#   - xxHash homepage: https://www.xxhash.com
#   - xxHash source repository: https://github.com/Cyan4973/xxHash
# ################################################################
# xxhsum: provides 32/64 bits hash of one or multiple files, or stdin
# ################################################################
Q = $(if $(filter 1,$(V) $(VERBOSE)),,@)

# Version numbers
SED ?= sed
SED_ERE_OPT ?= -E
LIBVER_MAJOR_SCRIPT:=`$(SED) -n '/define XXH_VERSION_MAJOR/s/.*[[:blank:]]\([0-9][0-9]*\).*/\1/p' < xxhash.h`
LIBVER_MINOR_SCRIPT:=`$(SED) -n '/define XXH_VERSION_MINOR/s/.*[[:blank:]]\([0-9][0-9]*\).*/\1/p' < xxhash.h`
LIBVER_PATCH_SCRIPT:=`$(SED) -n '/define XXH_VERSION_RELEASE/s/.*[[:blank:]]\([0-9][0-9]*\).*/\1/p' < xxhash.h`
LIBVER_MAJOR := $(shell echo $(LIBVER_MAJOR_SCRIPT))
LIBVER_MINOR := $(shell echo $(LIBVER_MINOR_SCRIPT))
LIBVER_PATCH := $(shell echo $(LIBVER_PATCH_SCRIPT))
LIBVER := $(LIBVER_MAJOR).$(LIBVER_MINOR).$(LIBVER_PATCH)

CFLAGS ?= -O3
DEBUGFLAGS+=-Wall -Wextra -Wconversion -Wcast-qual -Wcast-align -Wshadow \
            -Wstrict-aliasing=1 -Wswitch-enum -Wdeclaration-after-statement \
            -Wstrict-prototypes -Wundef -Wpointer-arith -Wformat-security \
            -Wvla -Wformat=2 -Winit-self -Wfloat-equal -Wwrite-strings \
            -Wredundant-decls -Wstrict-overflow=2
CFLAGS += $(DEBUGFLAGS) $(MOREFLAGS)
FLAGS   = $(CFLAGS) $(CPPFLAGS)
XXHSUM_VERSION = $(LIBVER)
UNAME := $(shell uname)

# Define *.exe as extension for Windows systems
ifneq (,$(filter Windows%,$(OS)))
EXT =.exe
else
EXT =
endif

# automatically enable runtime vector dispatch on x86/64 targets
detect_x86_arch = $(shell $(CC) -dumpmachine | grep -E 'i[3-6]86|x86_64')
ifneq ($(strip $(call detect_x86_arch)),)
    #note: can be overridden at compile time, by setting DISPATCH=0
    DISPATCH ?= 1
endif

ifeq ($(NODE_JS),1)
    # Link in unrestricted filesystem support
    LDFLAGS += -sNODERAWFS
    # Set flag to fix isatty() support
    CPPFLAGS += -DXSUM_NODE_JS=1
endif

# OS X linker doesn't support -soname, and use different extension
# see: https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/DynamicLibraryDesignGuidelines.html
ifeq ($(UNAME), Darwin)
	SHARED_EXT = dylib
	SHARED_EXT_MAJOR = $(LIBVER_MAJOR).$(SHARED_EXT)
	SHARED_EXT_VER = $(LIBVER).$(SHARED_EXT)
	SONAME_FLAGS = -install_name $(LIBDIR)/libxxhash.$(SHARED_EXT_MAJOR) -compatibility_version $(LIBVER_MAJOR) -current_version $(LIBVER)
else
	SONAME_FLAGS = -Wl,-soname=libxxhash.$(SHARED_EXT).$(LIBVER_MAJOR)
	SHARED_EXT = so
	SHARED_EXT_MAJOR = $(SHARED_EXT).$(LIBVER_MAJOR)
	SHARED_EXT_VER = $(SHARED_EXT).$(LIBVER)
endif

LIBXXH = libxxhash.$(SHARED_EXT_VER)

XXHSUM_SRC_DIR = cli
XXHSUM_SPLIT_SRCS = $(XXHSUM_SRC_DIR)/xxhsum.c \
                    $(XXHSUM_SRC_DIR)/xsum_os_specific.c \
                    $(XXHSUM_SRC_DIR)/xsum_arch.c \
                    $(XXHSUM_SRC_DIR)/xsum_output.c \
                    $(XXHSUM_SRC_DIR)/xsum_sanity_check.c \
                    $(XXHSUM_SRC_DIR)/xsum_bench.c
XXHSUM_SPLIT_OBJS = $(XXHSUM_SPLIT_SRCS:.c=.o)
XXHSUM_HEADERS = $(XXHSUM_SRC_DIR)/xsum_config.h \
                 $(XXHSUM_SRC_DIR)/xsum_arch.h \
                 $(XXHSUM_SRC_DIR)/xsum_os_specific.h \
                 $(XXHSUM_SRC_DIR)/xsum_output.h \
                 $(XXHSUM_SRC_DIR)/xsum_sanity_check.h \
                 $(XXHSUM_SRC_DIR)/xsum_bench.h

## generate CLI and libraries in release mode (default for `make`)
.PHONY: default
default: DEBUGFLAGS=
default: lib xxhsum_and_links

.PHONY: all
all: lib xxhsum xxhsum_inlinedXXH

## xxhsum is the command line interface (CLI)
ifeq ($(DISPATCH),1)
xxhsum: CPPFLAGS += -DXXHSUM_DISPATCH=1
xxhsum: xxh_x86dispatch.o
endif
xxhsum: xxhash.o $(XXHSUM_SPLIT_OBJS)
	$(CC) $(FLAGS) $^ $(LDFLAGS) -o $@$(EXT)

xxhsum32: CFLAGS += -m32  ## generate CLI in 32-bits mode
xxhsum32: xxhash.c $(XXHSUM_SPLIT_SRCS) ## do not generate object (avoid mixing different ABI)
	$(CC) $(FLAGS) $^ $(LDFLAGS) -o $@$(EXT)

## dispatch only works for x86/x64 systems
dispatch: CPPFLAGS += -DXXHSUM_DISPATCH=1
dispatch: xxhash.o xxh_x86dispatch.o $(XXHSUM_SPLIT_SRCS)
	$(CC) $(FLAGS) $^ $(LDFLAGS) -o $@$(EXT)

xxhash.o: xxhash.c xxhash.h
xxhsum.o: $(XXHSUM_SRC_DIR)/xxhsum.c $(XXHSUM_HEADERS) \
    xxhash.h xxh_x86dispatch.h
xxh_x86dispatch.o: xxh_x86dispatch.c xxh_x86dispatch.h xxhash.h

.PHONY: xxhsum_and_links
xxhsum_and_links: xxhsum xxh32sum xxh64sum xxh128sum xxh3sum

xxh32sum xxh64sum xxh128sum xxh3sum: xxhsum
	ln -sf $<$(EXT) $@$(EXT)

xxhsum_inlinedXXH: CPPFLAGS += -DXXH_INLINE_ALL
xxhsum_inlinedXXH: $(XXHSUM_SPLIT_SRCS)
	$(CC) $(FLAGS) $< -o $@$(EXT)


# library

libxxhash.a: ARFLAGS = rcs
libxxhash.a: xxhash.o
	$(AR) $(ARFLAGS) $@ $^

$(LIBXXH): LDFLAGS += -shared
ifeq (,$(filter Windows%,$(OS)))
$(LIBXXH): CFLAGS += -fPIC
endif
ifeq ($(LIBXXH_DISPATCH),1)
$(LIBXXH): xxh_x86dispatch.c
endif
$(LIBXXH): xxhash.c
	$(CC) $(FLAGS) $^ $(LDFLAGS) $(SONAME_FLAGS) -o $@
	ln -sf $@ libxxhash.$(SHARED_EXT_MAJOR)
	ln -sf $@ libxxhash.$(SHARED_EXT)

.PHONY: libxxhash
libxxhash:  ## generate dynamic xxhash library
libxxhash: $(LIBXXH)

.PHONY: lib
lib:  ## generate static and dynamic xxhash libraries
lib: libxxhash.a libxxhash

# helper targets

AWK  = awk
GREP = grep
SORT = sort
NM   = nm

.PHONY: list
list:  ## list all Makefile targets
	$(Q)$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | $(AWK) -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | $(SORT) | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

.PHONY: help
help:  ## list documented targets
	$(Q)$(GREP) -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	$(SORT) | \
	$(AWK) 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: clean
clean:  ## remove all build artifacts
	$(Q)$(RM) -r *.dSYM   # Mac OS-X specific
	$(Q)$(RM) core *.o *.obj *.$(SHARED_EXT) *.$(SHARED_EXT).* *.a libxxhash.pc
	$(Q)$(RM) xxhsum$(EXT) xxhsum32$(EXT) xxhsum_inlinedXXH$(EXT) dispatch$(EXT)
	$(Q)$(RM) xxhsum.wasm xxhsum.js xxhsum.html
	$(Q)$(RM) xxh32sum$(EXT) xxh64sum$(EXT) xxh128sum$(EXT) xxh3sum$(EXT)
	$(Q)$(RM) fuzzer
	$(Q)$(RM) $(XXHSUM_SRC_DIR)/*.o $(XXHSUM_SRC_DIR)/*.obj
	$(MAKE) -C tests clean
	$(MAKE) -C tests/bench clean
	$(MAKE) -C tests/collisions clean
	@echo cleaning completed


# =================================================
# tests
# =================================================

# make check can be run with cross-compiled binaries on emulated environments (qemu user mode)
# by setting $(RUN_ENV) to the target emulation environment
.PHONY: check
check: xxhsum test_sanity   ## basic tests for xxhsum CLI, set RUN_ENV for emulated environments
	# stdin
	# If you get "Wrong parameters" on Emscripten+Node.js, recompile with `NODE_JS=1`
	$(RUN_ENV) ./xxhsum$(EXT) < xxhash.c
	# multiple files
	$(RUN_ENV) ./xxhsum$(EXT) xxhash.*
	# internal bench
	$(RUN_ENV) ./xxhsum$(EXT) -bi0
	# long bench command
	$(RUN_ENV) ./xxhsum$(EXT) --benchmark-all -i0
	# bench multiple variants
	$(RUN_ENV) ./xxhsum$(EXT) -b1,2,3 -i0
	# file bench
	$(RUN_ENV) ./xxhsum$(EXT) -bi0 xxhash.c
	# 32-bit
	$(RUN_ENV) ./xxhsum$(EXT) -H0 xxhash.c
	# 128-bit
	$(RUN_ENV) ./xxhsum$(EXT) -H2 xxhash.c
	# XXH3 (enforce BSD style)
	$(RUN_ENV) ./xxhsum$(EXT) -H3 xxhash.c | grep "XXH3"
	# request incorrect variant
	$(RUN_ENV) ./xxhsum$(EXT) -H9 xxhash.c ; test $$? -eq 1
	@printf "\n .......   checks completed successfully   ....... \n"

.PHONY: test-unicode
test-unicode:
	$(MAKE) -C tests test_unicode

.PHONY: test_sanity
test_sanity:
	$(MAKE) -C tests test_sanity

.PHONY: test-mem
VALGRIND = valgrind --leak-check=yes --error-exitcode=1
test-mem: RUN_ENV = $(VALGRIND)
test-mem: xxhsum check

.PHONY: test32
test32: xxhsum32
	@echo ---- test 32-bit ----
	./xxhsum32 -bi0 xxhash.c

TEST_FILES = xxhsum$(EXT) xxhash.c xxhash.h
.PHONY: test-xxhsum-c
test-xxhsum-c: xxhsum
	# xxhsum to/from pipe
	./xxhsum $(TEST_FILES) | ./xxhsum -c -
	./xxhsum -H0 $(TEST_FILES) | ./xxhsum -c -
	# xxhsum -c is unable to verify checksum of file from STDIN (#470)
	./xxhsum < README.md > .test.README.md.xxh
	./xxhsum -c .test.README.md.xxh < README.md
	# xxhsum -q does not display "Loading" message into stderr (#251)
	! ./xxhsum -q $(TEST_FILES) 2>&1 | grep Loading
	# xxhsum does not display "Loading" message into stderr either
	! ./xxhsum $(TEST_FILES) 2>&1 | grep Loading
	# Check that xxhsum do display filename that it failed to open.
	LC_ALL=C ./xxhsum nonexistent 2>&1 | grep "Error: Could not open 'nonexistent'"
	# xxhsum to/from file, shell redirection
	./xxhsum $(TEST_FILES) > .test.xxh64
	./xxhsum --tag $(TEST_FILES) > .test.xxh64_tag
	./xxhsum --little-endian $(TEST_FILES) > .test.le_xxh64
	./xxhsum --tag --little-endian $(TEST_FILES) > .test.le_xxh64_tag
	./xxhsum -H0 $(TEST_FILES) > .test.xxh32
	./xxhsum -H0 --tag $(TEST_FILES) > .test.xxh32_tag
	./xxhsum -H0 --little-endian $(TEST_FILES) > .test.le_xxh32
	./xxhsum -H0 --tag --little-endian $(TEST_FILES) > .test.le_xxh32_tag
	./xxhsum -H2 $(TEST_FILES) > .test.xxh128
	./xxhsum -H2 --tag $(TEST_FILES) > .test.xxh128_tag
	./xxhsum -H2 --little-endian $(TEST_FILES) > .test.le_xxh128
	./xxhsum -H2 --tag --little-endian $(TEST_FILES) > .test.le_xxh128_tag
	./xxhsum -H3 $(TEST_FILES) > .test.xxh3
	./xxhsum -H3 --tag $(TEST_FILES) > .test.xxh3_tag
	./xxhsum -H3 --little-endian $(TEST_FILES) > .test.le_xxh3
	./xxhsum -H3 --tag --little-endian $(TEST_FILES) > .test.le_xxh3_tag
	./xxhsum -c .test.xxh*
	./xxhsum -c --little-endian .test.le_xxh*
	./xxhsum -c .test.*_tag
	# read list of files from stdin
	./xxhsum -c < .test.xxh32
	./xxhsum -c < .test.xxh64
	./xxhsum -c < .test.xxh128
	./xxhsum -c < .test.xxh3
	cat .test.xxh* | ./xxhsum -c -
	# check variant with '*' marker as second separator
	$(SED) 's/  / \*/' .test.xxh32 | ./xxhsum -c
	# bsd-style output
	./xxhsum --tag xxhsum* | $(GREP) XXH64
	./xxhsum --tag -H0 xxhsum* | $(GREP) XXH32
	./xxhsum --tag -H1 xxhsum* | $(GREP) XXH64
	./xxhsum --tag -H2 xxhsum* | $(GREP) XXH128
	./xxhsum --tag -H3 xxhsum* | $(GREP) XXH3
	./xxhsum       -H3 xxhsum* | $(GREP) XXH3_ # prefix for GNU format
	./xxhsum --tag -H32 xxhsum* | $(GREP) XXH32
	./xxhsum --tag -H64 xxhsum* | $(GREP) XXH64
	./xxhsum --tag -H128 xxhsum* | $(GREP) XXH128
	./xxhsum --tag -H0 --little-endian xxhsum* | $(GREP) XXH32_LE
	./xxhsum --tag -H1 --little-endian xxhsum* | $(GREP) XXH64_LE
	./xxhsum --tag -H2 --little-endian xxhsum* | $(GREP) XXH128_LE
	./xxhsum --tag -H3 --little-endian xxhsum* | $(GREP) XXH3_LE
	./xxhsum --tag -H32 --little-endian xxhsum* | $(GREP) XXH32_LE
	./xxhsum --tag -H64 --little-endian xxhsum* | $(GREP) XXH64_LE
	./xxhsum --tag -H128 --little-endian xxhsum* | $(GREP) XXH128_LE
	# check bsd-style
	./xxhsum --tag xxhsum* | ./xxhsum -c
	./xxhsum --tag -H32 --little-endian xxhsum* | ./xxhsum -c
	# xxhsum -c warns improperly format lines.
	echo '12345678 ' >>.test.xxh32
	./xxhsum -c .test.xxh32 | $(GREP) improperly
	echo '123456789  file' >>.test.xxh64
	./xxhsum -c .test.xxh64 | $(GREP) improperly
	# Expects "FAILED"
	echo "0000000000000000  LICENSE" | ./xxhsum -c -; test $$? -eq 1
	echo "00000000  LICENSE" | ./xxhsum -c -; test $$? -eq 1
	# Expects "FAILED open or read"
	echo "0000000000000000  test-expects-file-not-found" | ./xxhsum -c -; test $$? -eq 1
	echo "00000000  test-expects-file-not-found" | ./xxhsum -c -; test $$? -eq 1
	# --filelist
	echo xxhash.c > .test.filenames
	$(RUN_ENV) ./xxhsum$(EXT) --filelist .test.filenames
	# --filelist from stdin
	cat .test.filenames | $(RUN_ENV) ./xxhsum$(EXT) --filelist
	@$(RM) .test.*

LIB_FUZZING_ENGINE?="-fsanitize=fuzzer"
CC_VERSION := $(shell $(CC) --version)
ifneq (,$(findstring clang,$(CC_VERSION)))
fuzzer: libxxhash.a fuzz/fuzzer.c
	$(CC) $(CFLAGS) $(LIB_FUZZING_ENGINE) -I. -o fuzzer fuzz/fuzzer.c -L. -Wl,-Bstatic -lxxhash -Wl,-Bdynamic
endif

.PHONY: test-filename-escape
test-filename-escape:
	$(MAKE) -C tests test_filename_escape

.PHONY: test-cli-comment-line
test-cli-comment-line:
	$(MAKE) -C tests test_cli_comment_line

.PHONY: test-cli-ignore-missing
test-cli-ignore-missing:
	$(MAKE) -C tests test_cli_ignore_missing

.PHONY: armtest
armtest: clean
	@echo ---- test ARM compilation ----
	CC=arm-linux-gnueabi-gcc MOREFLAGS="-Werror -static" $(MAKE) xxhsum

.PHONY: arm64test
arm64test: clean
	@echo ---- test ARM64 compilation ----
	CC=aarch64-linux-gnu-gcc MOREFLAGS="-Werror -static" $(MAKE) xxhsum

.PHONY: clangtest
clangtest: clean
	@echo ---- test clang compilation ----
	CC=clang MOREFLAGS="-Werror -Wconversion -Wno-sign-conversion" $(MAKE) all

.PHONY: gcc-og-test
gcc-og-test: clean
	@echo ---- test gcc -Og compilation ----
	CFLAGS="-Og -Wall -Wextra -Wundef -Wshadow -Wcast-align -Werror -fPIC" CPPFLAGS="-DXXH_NO_INLINE_HINTS" MOREFLAGS="-Werror" $(MAKE) all

.PHONY: cxxtest
cxxtest: clean
	@echo ---- test C++ compilation ----
	CC="$(CXX) -Wno-deprecated" $(MAKE) all CFLAGS="-O3 -Wall -Wextra -Wundef -Wshadow -Wcast-align -Werror -fPIC"

# In strict C90 mode, there is no `long long` type support,
# consequently, only XXH32 can be compiled.
.PHONY: c90test
ifeq ($(NO_C90_TEST),true)
c90test:
	@echo no c90 compatibility test
else
c90test: CPPFLAGS += -DXXH_NO_LONG_LONG
c90test: CFLAGS += -std=c90 -Werror -pedantic
c90test: xxhash.c
	@echo ---- test strict C90 compilation [xxh32 only] ----
	$(RM) xxhash.o
	$(CC) $(FLAGS) $^ -c
	$(NM) xxhash.o | $(GREP) XXH64 ; test $$? -eq 1
	$(RM) xxhash.o
endif

.PHONY: noxxh3test
noxxh3test: CPPFLAGS += -DXXH_NO_XXH3
noxxh3test: CFLAGS += -Werror -pedantic -Wno-long-long  # XXH64 requires long long support
noxxh3test: OFILE = xxh_noxxh3.o
noxxh3test: xxhash.c
	@echo ---- test compilation without XXH3 ----
	$(CC) $(FLAGS) -c $^ -o $(OFILE)
	$(NM) $(OFILE) | $(GREP) XXH3_ ; test $$? -eq 1
	$(RM) $(OFILE)

.PHONY: nostreamtest
nostreamtest: CPPFLAGS += -DXXH_NO_STREAM
nostreamtest: CFLAGS += -Werror -pedantic -Wno-long-long  # XXH64 requires long long support
nostreamtest: OFILE = xxh_nostream.o
nostreamtest: xxhash.c
	@echo ---- test compilation without streaming ----
	$(CC) $(FLAGS) -c $^ -o $(OFILE)
	$(NM) $(OFILE) | $(GREP) update ; test $$? -eq 1
	$(RM) $(OFILE)

.PHONY: nostdlibtest
nostdlibtest: CPPFLAGS += -DXXH_NO_STDLIB
nostdlibtest: CFLAGS += -Werror -pedantic -Wno-long-long  # XXH64 requires long long support
nostdlibtest: OFILE = xxh_nostdlib.o
nostdlibtest: xxhash.c
	@echo ---- test compilation without \<stdlib.h\> ----
	$(CC) $(FLAGS) -c $^ -o $(OFILE)
	$(NM) $(OFILE) | $(GREP) "U _free\|U free" ; test $$? -eq 1
	$(RM) $(OFILE)

.PHONY: usan
usan: CC=clang
usan: CXX=clang++
usan:  ## check CLI runtime for undefined behavior, using clang's sanitizer
	@echo ---- check undefined behavior - sanitize ----
	$(MAKE) clean
	$(MAKE) test CC=$(CC) CXX=$(CXX) MOREFLAGS="-g -fsanitize=undefined -fno-sanitize-recover=all"

.PHONY: staticAnalyze
SCANBUILD ?= scan-build
staticAnalyze: clean  ## check C source files using $(SCANBUILD) static analyzer
	@echo ---- static analyzer - $(SCANBUILD) ----
	CFLAGS="-g -Werror" $(SCANBUILD) --status-bugs -v $(MAKE) all

CPPCHECK ?= cppcheck
.PHONY: cppcheck
cppcheck:  ## check C source files using $(CPPCHECK) static analyzer
	@echo ---- static analyzer - $(CPPCHECK) ----
	$(CPPCHECK) . --force --enable=warning,portability,performance,style --error-exitcode=1 > /dev/null

.PHONY: namespaceTest
namespaceTest:  ## ensure XXH_NAMESPACE redefines all public symbols
	$(CC) -c xxhash.c
	$(CC) -DXXH_NAMESPACE=TEST_ -c xxhash.c -o xxhash2.o
	$(CC) xxhash.o xxhash2.o $(XXHSUM_SPLIT_SRCS)  -o xxhsum2  # will fail if one namespace missing (symbol collision)
	$(RM) *.o xxhsum2  # clean

MAN = $(XXHSUM_SRC_DIR)/xxhsum.1
MD2ROFF ?= ronn
MD2ROFF_FLAGS ?= --roff --warnings --manual="User Commands" --organization="xxhsum $(XXHSUM_VERSION)"
$(MAN): $(XXHSUM_SRC_DIR)/xxhsum.1.md xxhash.h
	cat $< | $(MD2ROFF) $(MD2ROFF_FLAGS) | $(SED) -n '/^\.\\\".*/!p' > $@

.PHONY: man
man: $(MAN)  ## generate man page from markdown source

.PHONY: clean-man
clean-man:
	$(RM) xxhsum.1

.PHONY: preview-man
preview-man: man
	man ./xxhsum.1

.PHONY: test
test: DEBUGFLAGS += -DXXH_DEBUGLEVEL=1
test: all namespaceTest check test-xxhsum-c c90test test-tools noxxh3test nostdlibtest

# this test checks that including "xxhash.h" multiple times and with different directives still compiles properly
.PHONY: test-multiInclude
test-multiInclude:
	$(MAKE) -C tests test_multiInclude

.PHONY: test-inline-notexposed
test-inline-notexposed: xxhsum_inlinedXXH
	$(NM) xxhsum_inlinedXXH | $(GREP) "t _XXH32_" ; test $$? -eq 1  # no XXH32 symbol should be left
	$(NM) xxhsum_inlinedXXH | $(GREP) "t _XXH64_" ; test $$? -eq 1  # no XXH64 symbol should be left

.PHONY: test-inline
test-inline: test-inline-notexposed test-multiInclude


.PHONY: test-all
test-all: CFLAGS += -Werror
test-all: test test32 test-unicode clangtest gcc-og-test cxxtest usan test-inline listL120 trailingWhitespace test-xxh-nnn-sums

.PHONY: test-tools
test-tools:
	CFLAGS=-Werror $(MAKE) -C tests/bench
	CFLAGS=-Werror $(MAKE) -C tests/collisions check

.PHONY: test-xxh-nnn-sums
test-xxh-nnn-sums: xxhsum_and_links
	./xxhsum    README.md > tmp.xxhsum.out    # xxhsum outputs xxh64
	./xxh32sum  README.md > tmp.xxh32sum.out
	./xxh64sum  README.md > tmp.xxh64sum.out
	./xxh128sum README.md > tmp.xxh128sum.out
	./xxh3sum   README.md > tmp.xxh3sum.out
	cat tmp.xxhsum.out
	cat tmp.xxh32sum.out
	cat tmp.xxh64sum.out
	cat tmp.xxh128sum.out
	cat tmp.xxh3sum.out
	./xxhsum -c tmp.xxhsum.out
	./xxhsum -c tmp.xxh32sum.out
	./xxhsum -c tmp.xxh64sum.out
	./xxhsum -c tmp.xxh128sum.out
	./xxhsum -c tmp.xxh3sum.out
	./xxh32sum -c tmp.xxhsum.out            ; test $$? -eq 1  # expects "no properly formatted"
	./xxh32sum -c tmp.xxh32sum.out
	./xxh32sum -c tmp.xxh64sum.out          ; test $$? -eq 1  # expects "no properly formatted"
	./xxh32sum -c tmp.xxh128sum.out         ; test $$? -eq 1  # expects "no properly formatted"
	./xxh32sum -c tmp.xxh3sum.out           ; test $$? -eq 1  # expects "no properly formatted"
	./xxh64sum -c tmp.xxhsum.out
	./xxh64sum -c tmp.xxh32sum.out          ; test $$? -eq 1  # expects "no properly formatted"
	./xxh64sum -c tmp.xxh64sum.out
	./xxh64sum -c tmp.xxh128sum.out         ; test $$? -eq 1  # expects "no properly formatted"
	./xxh64sum -c tmp.xxh3sum.out           ; test $$? -eq 1  # expects "no properly formatted"
	./xxh128sum -c tmp.xxhsum.out           ; test $$? -eq 1  # expects "no properly formatted"
	./xxh128sum -c tmp.xxh32sum.out         ; test $$? -eq 1  # expects "no properly formatted"
	./xxh128sum -c tmp.xxh64sum.out         ; test $$? -eq 1  # expects "no properly formatted"
	./xxh128sum -c tmp.xxh128sum.out
	./xxh128sum -c tmp.xxh3sum.out          ; test $$? -eq 1  # expects "no properly formatted"
	./xxh3sum -c tmp.xxhsum.out             ; test $$? -eq 1  # expects "no properly formatted"
	./xxh3sum -c tmp.xxh32sum.out           ; test $$? -eq 1  # expects "no properly formatted"
	./xxh3sum -c tmp.xxh64sum.out           ; test $$? -eq 1  # expects "no properly formatted"
	./xxh3sum -c tmp.xxh128sum.out          ; test $$? -eq 1  # expects "no properly formatted"
	./xxh3sum -c tmp.xxh3sum.out

.PHONY: listL120
listL120:  # extract lines >= 120 characters in *.{c,h}, by Takayuki Matsuoka (note: $$, for Makefile compatibility)
	find . -type f -name '*.c' -o -name '*.h' | while read -r filename; do awk 'length > 120 {print FILENAME "(" FNR "): " $$0}' $$filename; done

.PHONY: trailingWhitespace
trailingWhitespace:
	! $(GREP) -E "`printf '[ \\t]$$'`" cli/*.c cli/*.h cli/*.1 *.c *.h LICENSE Makefile cmake_unofficial/CMakeLists.txt

.PHONY: lint-unicode
lint-unicode:
	./tests/unicode_lint.sh

# =========================================================
# make install is validated only for the following targets
# =========================================================
ifneq (,$(filter Linux Darwin GNU/kFreeBSD GNU Haiku OpenBSD FreeBSD NetBSD DragonFly SunOS CYGWIN% , $(UNAME)))

DESTDIR     ?=
# directory variables: GNU conventions prefer lowercase
# see https://www.gnu.org/prep/standards/html_node/Makefile-Conventions.html
# support both lower and uppercase (BSD), use uppercase in script
prefix      ?= /usr/local
PREFIX      ?= $(prefix)
exec_prefix ?= $(PREFIX)
EXEC_PREFIX ?= $(exec_prefix)
libdir      ?= $(EXEC_PREFIX)/lib
LIBDIR      ?= $(libdir)
includedir  ?= $(PREFIX)/include
INCLUDEDIR  ?= $(includedir)
bindir      ?= $(EXEC_PREFIX)/bin
BINDIR      ?= $(bindir)
datarootdir ?= $(PREFIX)/share
mandir      ?= $(datarootdir)/man
man1dir     ?= $(mandir)/man1

ifneq (,$(filter $(UNAME),FreeBSD NetBSD DragonFly))
PKGCONFIGDIR ?= $(PREFIX)/libdata/pkgconfig
else
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig
endif

ifneq (,$(filter $(UNAME),OpenBSD NetBSD DragonFly SunOS))
MANDIR  ?= $(PREFIX)/man/man1
else
MANDIR  ?= $(man1dir)
endif

ifneq (,$(filter $(UNAME),SunOS))
INSTALL ?= ginstall
else
INSTALL ?= install
endif

INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_DATA    ?= $(INSTALL) -m 644
MAKE_DIR        ?= $(INSTALL) -d -m 755


# Escape special symbols by putting each character into its separate class
EXEC_PREFIX_REGEX ?= $(shell echo "$(EXEC_PREFIX)" | $(SED) $(SED_ERE_OPT) -e "s/([^^])/[\1]/g" -e "s/\\^/\\\\^/g")
PREFIX_REGEX ?= $(shell echo "$(PREFIX)" | $(SED) $(SED_ERE_OPT) -e "s/([^^])/[\1]/g" -e "s/\\^/\\\\^/g")

PCLIBDIR ?= $(shell echo "$(LIBDIR)"     | $(SED) -n $(SED_ERE_OPT) -e "s@^$(EXEC_PREFIX_REGEX)(/|$$)@@p")
PCINCDIR ?= $(shell echo "$(INCLUDEDIR)" | $(SED) -n $(SED_ERE_OPT) -e "s@^$(PREFIX_REGEX)(/|$$)@@p")
PCEXECDIR?= $(if $(filter $(PREFIX),$(EXEC_PREFIX)),$$\{prefix\},$(EXEC_PREFIX))

ifeq (,$(PCLIBDIR))
# Additional prefix check is required, since the empty string is technically a
# valid PCLIBDIR
ifeq (,$(shell echo "$(LIBDIR)" | $(SED) -n $(SED_ERE_OPT) -e "\\@^$(EXEC_PREFIX_REGEX)(/|$$)@ p"))
$(error configured libdir ($(LIBDIR)) is outside of exec_prefix ($(EXEC_PREFIX)), can't generate pkg-config file)
endif
endif

ifeq (,$(PCINCDIR))
# Additional prefix check is required, since the empty string is technically a
# valid PCINCDIR
ifeq (,$(shell echo "$(INCLUDEDIR)" | $(SED) -n $(SED_ERE_OPT) -e "\\@^$(PREFIX_REGEX)(/|$$)@ p"))
$(error configured includedir ($(INCLUDEDIR)) is outside of prefix ($(PREFIX)), can't generate pkg-config file)
endif
endif

libxxhash.pc: libxxhash.pc.in
	@echo creating pkgconfig
	$(Q)$(SED) $(SED_ERE_OPT) -e 's|@PREFIX@|$(PREFIX)|' \
          -e 's|@EXECPREFIX@|$(PCEXECDIR)|' \
          -e 's|@LIBDIR@|$$\{exec_prefix\}/$(PCLIBDIR)|' \
          -e 's|@INCLUDEDIR@|$$\{prefix\}/$(PCINCDIR)|' \
          -e 's|@VERSION@|$(LIBVER)|' \
          $< > $@


install_libxxhash.a: libxxhash.a
	@echo Installing libxxhash.a
	$(Q)$(MAKE_DIR) $(DESTDIR)$(LIBDIR)
	$(Q)$(INSTALL_DATA) libxxhash.a $(DESTDIR)$(LIBDIR)

install_libxxhash: libxxhash
	@echo Installing libxxhash
	$(Q)$(MAKE_DIR) $(DESTDIR)$(LIBDIR)
	$(Q)$(INSTALL_PROGRAM) $(LIBXXH) $(DESTDIR)$(LIBDIR)
	$(Q)ln -sf $(LIBXXH) $(DESTDIR)$(LIBDIR)/libxxhash.$(SHARED_EXT_MAJOR)
	$(Q)ln -sf $(LIBXXH) $(DESTDIR)$(LIBDIR)/libxxhash.$(SHARED_EXT)

install_libxxhash.includes:
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(INCLUDEDIR)   # includes
	$(Q)$(INSTALL_DATA) xxhash.h $(DESTDIR)$(INCLUDEDIR)
	$(Q)$(INSTALL_DATA) xxh3.h $(DESTDIR)$(INCLUDEDIR) # for compatibility, will be removed in v0.9.0
ifeq ($(LIBXXH_DISPATCH),1)
	$(Q)$(INSTALL_DATA) xxh_x86dispatch.h $(DESTDIR)$(INCLUDEDIR)
endif

install_libxxhash.pc: libxxhash.pc
	@echo Installing pkgconfig
	$(Q)$(MAKE_DIR) $(DESTDIR)$(PKGCONFIGDIR)/
	$(Q)$(INSTALL_DATA) libxxhash.pc $(DESTDIR)$(PKGCONFIGDIR)/

install_xxhsum: xxhsum
	@echo Installing xxhsum
	$(Q)$(MAKE_DIR) $(DESTDIR)$(BINDIR)/
	$(Q)$(INSTALL_PROGRAM) xxhsum$(EXT) $(DESTDIR)$(BINDIR)/xxhsum$(EXT)
	$(Q)ln -sf xxhsum$(EXT) $(DESTDIR)$(BINDIR)/xxh32sum$(EXT)
	$(Q)ln -sf xxhsum$(EXT) $(DESTDIR)$(BINDIR)/xxh64sum$(EXT)
	$(Q)ln -sf xxhsum$(EXT) $(DESTDIR)$(BINDIR)/xxh128sum$(EXT)
	$(Q)ln -sf xxhsum$(EXT) $(DESTDIR)$(BINDIR)/xxh3sum$(EXT)

install_man:
	@echo Installing man pages
	$(Q)$(MAKE_DIR) $(DESTDIR)$(MANDIR)/
	$(Q)$(INSTALL_DATA) $(MAN) $(DESTDIR)$(MANDIR)/xxhsum.1
	$(Q)ln -sf xxhsum.1 $(DESTDIR)$(MANDIR)/xxh32sum.1
	$(Q)ln -sf xxhsum.1 $(DESTDIR)$(MANDIR)/xxh64sum.1
	$(Q)ln -sf xxhsum.1 $(DESTDIR)$(MANDIR)/xxh128sum.1
	$(Q)ln -sf xxhsum.1 $(DESTDIR)$(MANDIR)/xxh3sum.1

.PHONY: install
## install libraries, CLI, links and man pages
install: install_libxxhash.a install_libxxhash install_libxxhash.includes install_libxxhash.pc install_xxhsum install_man
	@echo xxhash installation completed

.PHONY: uninstall
uninstall:  ## uninstall libraries, CLI, links and man page
	$(Q)$(RM) $(DESTDIR)$(LIBDIR)/libxxhash.a
	$(Q)$(RM) $(DESTDIR)$(LIBDIR)/libxxhash.$(SHARED_EXT)
	$(Q)$(RM) $(DESTDIR)$(LIBDIR)/libxxhash.$(SHARED_EXT_MAJOR)
	$(Q)$(RM) $(DESTDIR)$(LIBDIR)/$(LIBXXH)
	$(Q)$(RM) $(DESTDIR)$(INCLUDEDIR)/xxhash.h
	$(Q)$(RM) $(DESTDIR)$(INCLUDEDIR)/xxh3.h
	$(Q)$(RM) $(DESTDIR)$(INCLUDEDIR)/xxh_x86dispatch.h
	$(Q)$(RM) $(DESTDIR)$(PKGCONFIGDIR)/libxxhash.pc
	$(Q)$(RM) $(DESTDIR)$(BINDIR)/xxh32sum
	$(Q)$(RM) $(DESTDIR)$(BINDIR)/xxh64sum
	$(Q)$(RM) $(DESTDIR)$(BINDIR)/xxh128sum
	$(Q)$(RM) $(DESTDIR)$(BINDIR)/xxh3sum
	$(Q)$(RM) $(DESTDIR)$(BINDIR)/xxhsum
	$(Q)$(RM) $(DESTDIR)$(MANDIR)/xxh32sum.1
	$(Q)$(RM) $(DESTDIR)$(MANDIR)/xxh64sum.1
	$(Q)$(RM) $(DESTDIR)$(MANDIR)/xxh128sum.1
	$(Q)$(RM) $(DESTDIR)$(MANDIR)/xxh3sum.1
	$(Q)$(RM) $(DESTDIR)$(MANDIR)/xxhsum.1
	@echo xxhsum successfully uninstalled

endif
