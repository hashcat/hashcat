##
## Author......: See docs/credits.txt
## License.....: MIT
##

# MinGW's CRT GLOB (for windows builds only)

EGREP              := egrep
MG                 := $(MAKECMDGOALS)

CRT_GLOB_FILE_NAME ?= CRT_glob.o


# we can skip the CRT_glob.o check/search if we do not build windows binaries

IS_WIN_BUILD32     := $(filter binaries,$(MG))$(filter win32,$(MG))$(filter hashcat32.exe,$(MG))
IS_WIN_BUILD64     := $(filter binaries,$(MG))$(filter win64,$(MG))$(filter hashcat64.exe,$(MG))

##
## win32
##

ifneq (,$(IS_WIN_BUILD32))

ifeq ($(UNAME),CYGWIN)
$(error Cross-compiling on $(UNAME) is not supported, please use the native target)
endif

ifeq ($(UNAME),MSYS2)
$(error Cross-compiling on $(UNAME) is not supported, please use the native target)
endif

# entering this code path means: we need to check for CRT_glob.o since we try to build binaries for windows operating systems

CRT_GLOB_LIB_PATH_32    ?= /usr/i686-w64-mingw32/lib/

CRT_GLOB_LIB_SYSROOT_32 := $(shell $(CC_WIN_32) --verbose 2>&1 | $(EGREP) -m 1 -o '(with-sysroot="[^"]"|with-sysroot=[^ ]*)' | $(SED) 's/^with-sysroot="\?\([^"]*\)"\?$$/\1/')

ifneq (,$(CRT_GLOB_LIB_SYSROOT_32))
CRT_GLOB_LIB_PATH_32    := $(CRT_GLOB_LIB_SYSROOT_32)
endif

CRT_GLOB_32 := $(shell $(FIND) "$(CRT_GLOB_LIB_PATH_32)" -name $(CRT_GLOB_FILE_NAME) -print -quit)

ifeq (,$(CRT_GLOB_32))
define WARNING_MESSAGE=


! The MinGW CRT GLOB library for 32-bit compilation was not found on your system. Please make sure that $(CRT_GLOB_FILE_NAME) exists
! ATTENTION: File globbing will be disabled

endef
$(warning $(WARNING_MESSAGE))
endif

endif

##
## win64
##

ifneq (,$(IS_WIN_BUILD64))

ifeq ($(UNAME),CYGWIN)
$(error Cross-compiling on $(UNAME) is not supported, please use the native target)
endif

ifeq ($(UNAME),MSYS2)
$(error Cross-compiling on $(UNAME) is not supported, please use the native target)
endif

# entering this code path means: we need to check for CRT_glob.o since we try to build binaries for windows operating systems

CRT_GLOB_LIB_PATH_64    ?= /usr/x86_64-w64-mingw32/lib/

CRT_GLOB_LIB_SYSROOT_64 := $(shell $(CC_WIN_64) --verbose 2>&1 | $(EGREP) -m 1 -o '(with-sysroot="[^"]"|with-sysroot=[^ ]*)' | $(SED) 's/^with-sysroot="\?\([^"]*\)"\?$$/\1/')

ifneq (,$(CRT_GLOB_LIB_SYSROOT_64))
CRT_GLOB_LIB_PATH_64    := $(CRT_GLOB_LIB_SYSROOT_64)
endif

CRT_GLOB_64 := $(shell $(FIND) "$(CRT_GLOB_LIB_PATH_64)" -name $(CRT_GLOB_FILE_NAME) -print -quit)

ifeq (,$(CRT_GLOB_64))
define WARNING_MESSAGE=


! The MinGW CRT GLOB library for 64-bit compilation was not found on your system. Please make sure that $(CRT_GLOB_FILE_NAME) exists
! ATTENTION: File globbing will be disabled

endef
$(warning $(WARNING_MESSAGE))
endif

endif

##
## win native
##

IS_WIN_BUILD_NATIVE := $(filter CYGWIN,$(UNAME))$(filter MSYS2,$(UNAME))

ifneq (,$(IS_WIN_BUILD_NATIVE))

# entering this code path means: we need to check for CRT_glob.o since we try to build binaries for windows operating systems

CRT_GLOB := $(shell $(FIND) / -name $(CRT_GLOB_FILE_NAME) -print -quit)

ifeq (,$(CRT_GLOB))
define WARNING_MESSAGE=


! The MinGW CRT GLOB library was not found on your system. Please make sure that $(CRT_GLOB_FILE_NAME) exists
! ATTENTION: File globbing will be disabled

endef
$(warning $(WARNING_MESSAGE))
endif

endif
