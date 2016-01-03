##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

GCC     := /usr/bin/x86_64-linux-gnu-gcc-4.6
ROOT    := ../../
CFLAGS  := -O2 -s -ansi -pipe -W -Wall -std=c99 -I$(ROOT)include/
LIBS    :=
TARGET  := gpu2cpu_rule_test
INCLUDE := $(ROOT)src/rp_gpu_on_cpu.c cpu_rules.c

all: ${TARGET}.c
	${GCC} ${CFLAGS} ${INCLUDE} $< -o ${TARGET}.bin ${LIBS}

clean:
	rm -f *.bin
