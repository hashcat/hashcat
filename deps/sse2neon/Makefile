ifndef CC
override CC = gcc
endif

ifndef CXX
override CXX = g++
endif

ifndef CROSS_COMPILE
    processor := $(shell uname -m)
else # CROSS_COMPILE was set
    CC = $(CROSS_COMPILE)gcc
    CXX = $(CROSS_COMPILE)g++
    CXXFLAGS += -static
    LDFLAGS += -static
    check_arm := $(shell echo | $(CROSS_COMPILE)cpp -dM - | grep " __ARM_ARCH " | cut -c20-)
    ifeq ($(check_arm),8)
        processor = aarch64
    else ifeq ($(check_arm),7) # detect ARMv7-A only
        processor = arm
    else
        $(error Unsupported cross-compiler)
    endif
endif

EXEC_WRAPPER =
ifdef CROSS_COMPILE
EXEC_WRAPPER = qemu-$(processor)
endif

# Follow platform-specific configurations
ARCH_CFLAGS ?=
ARCH_CFLAGS_IS_SET =
ifeq ($(ARCH_CFLAGS),)
    ARCH_CFLAGS_IS_SET = true
endif
ifeq ($(ARCH_CFLAGS),none)
    ARCH_CFLAGS_IS_SET = true
endif
ifdef ARCH_CFLAGS_IS_SET
    ifeq ($(processor),$(filter $(processor),aarch64 arm64))
        override ARCH_CFLAGS := -march=armv8-a+fp+simd
    else ifeq ($(processor),$(filter $(processor),i386 x86_64))
        override ARCH_CFLAGS := -maes -mpclmul -mssse3 -msse4.2
    else ifeq ($(processor),$(filter $(processor),arm armv7 armv7l))
        override ARCH_CFLAGS := -mfpu=neon
    else
        $(error Unsupported architecture)
    endif
endif

FEATURE ?=
ifneq ($(FEATURE),)
ifneq ($(FEATURE),none)
COMMA:= ,
ARCH_CFLAGS := $(ARCH_CFLAGS)+$(subst $(COMMA),+,$(FEATURE))
endif
endif

CXXFLAGS += -Wall -Wcast-qual -Wconversion -I. $(ARCH_CFLAGS) -std=gnu++14
LDFLAGS	+= -lm
OBJS = \
    tests/binding.o \
    tests/common.o \
    tests/impl.o \
    tests/main.o
deps := $(OBJS:%.o=%.o.d)

.SUFFIXES: .o .cpp
.cpp.o:
	$(CXX) -o $@ $(CXXFLAGS) -c -MMD -MF $@.d $<

EXEC = tests/main

$(EXEC): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^

check: tests/main
ifeq ($(processor),$(filter $(processor),aarch64 arm64 arm armv7l))
	$(CC) $(ARCH_CFLAGS) -c sse2neon.h
endif
	$(EXEC_WRAPPER) $^

indent:
	@echo "Formatting files with clang-format.."
	@if ! hash clang-format-18; then echo "clang-format-18 is required to indent"; fi
	clang-format-18 -i sse2neon.h tests/*.cpp tests/*.h

.PHONY: clean check format
clean:
	$(RM) $(OBJS) $(EXEC) $(deps) sse2neon.h.gch

-include $(deps)
