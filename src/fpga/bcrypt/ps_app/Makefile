##
## Author......: See docs/credits.txt
## License.....: MIT
##

CROSS   ?= arm-none-eabi-

CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
NM      := $(CROSS)nm

AEAD_DIR := ../../../bridges/fpga

CFLAGS  := -mcpu=cortex-a9 -marm -ffreestanding -nostdlib -nostartfiles -mno-unaligned-access -O2 -Wall -Wextra -I$(AEAD_DIR)
LDFLAGS := -Wl,--build-id=none -T app.ld

all: app.bin

app.elf: start.S app.c gem.c udp.c gem.h udp.h proto.h app.ld $(AEAD_DIR)/hcfpga_aead.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ start.S app.c gem.c udp.c

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@
	@
	@
	@$(OBJDUMP) -d app.elf | grep -q '^00000000 <_start>:' \
	  || { echo "  _start is NOT at address 0, refusing to ship this image"; exit 1; }
	@
	@
	@test "$$(( 0x$$($(NM) app.elf | sed -n 's/^\([0-9a-f]*\) . __image_end$$/\1/p') ))" = "$$(stat -c%s app.bin)" \
	  || { echo "  __image_end is not the end of app.bin, refusing to ship this image"; exit 1; }
	@echo "  app.bin: $$(stat -c%s app.bin) bytes, _start at 0"

HEADER  := ../../../bridges/fpga/artyz7_ps_app.h

header: app.bin
	@./gen_ps_app.py app.bin $(HEADER) "$$($(CC) --version | head -1)"

clean:
	rm -f app.elf app.bin

.PHONY: all clean header
