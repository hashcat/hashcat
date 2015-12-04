##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

GCC     ?= /usr/bin/x86_64-linux-gnu-gcc
MINGW   ?= i686-w64-mingw32-gcc
ROOT    := ../..
CFLAGS  := -O2 -s -std=c99 -pipe -W -Wall -I$(ROOT)/include/ -I../rules_test/
SRC     := ./rules_optimize.c
TARGET  := $(ROOT)/extra/rules_optimize/rules_optimize

all: ${TARGET}.bin ${TARGET}.exe

${TARGET}.bin: $(SRC)
	${GCC} ${CFLAGS} ../rules_test/cpu_rules.c $< -o ${TARGET}.bin

${TARGET}.exe: $(SRC)
	${MINGW} ${CFLAGS} ../rules_test/cpu_rules.c $< -o ${TARGET}.exe

clean:
	rm -f $(TARGET)*.bin $(TARGET)*.exe
