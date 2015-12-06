##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

GCC     := /usr/bin/x86_64-linux-gnu-gcc-4.6
ROOT    := ../../
CFLAGS  := -O2 -s -ansi -pipe -W -Wall -I$(ROOT)include/
LIBS    :=
TARGET  := gpu2cpu_rule_test
INCLUDE := $(ROOT)src/rp_gpu_on_cpu.cpp cpu_rules.cpp

all: ${TARGET}.cpp
	${GCC} ${CFLAGS} ${INCLUDE} $< -o ${TARGET}.bin ${LIBS}

clean:
	rm -f *.bin
