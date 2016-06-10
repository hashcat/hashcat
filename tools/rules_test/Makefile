##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

GCC     := gcc
ROOT    := ../..
CFLAGS  := -O2 -s -pipe -W -Wall -std=c99 -I$(ROOT)/include/ -I$(ROOT)/OpenCL/
LIBS    :=
TARGET  := kernel2cpu_rule_test
INCLUDE := $(ROOT)/src/rp_kernel_on_cpu.c cpu_rules.c

all: ${TARGET}.c
	${GCC} ${CFLAGS} ${INCLUDE} $< -o ${TARGET}.bin ${LIBS}

clean:
	rm -f *.bin
