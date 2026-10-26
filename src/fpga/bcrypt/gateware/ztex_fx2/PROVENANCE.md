# ZTEX FX2 shell provenance

This directory is the shell that connects `hcfpga_top` to a ZTEX USB-FPGA Module through the Cypress FX2 in slave FIFO mode. Two of its files are ZTEX's, taken unmodified from ZTEX's own SDK. The rest was written for hashcat.

## Files taken from ZTEX

| File | Origin | Licence |
|---|---|---|
| `ezusb_io.v` | `ztex/default/fpga-fx2/ezusb_io.v` | Solderpad Hardware License 0.51 |
| `ezusb_lsi.v` | `ztex/default/fpga-fx2/ezusb_lsi.v` | Solderpad Hardware License 0.51 |

Upstream: the ZTEX SDK, `ztex-240611.tar.bz2`, https://www.ztex.de. Copyright (C) 2009-2023 ZTEX GmbH.

**Both files are byte-for-byte identical to upstream** and retain ZTEX's headers, including the licence
text. They implement the FPGA half of a protocol whose other half is the microcontroller firmware on
the board. Changing either file would alter a protocol contract without control of both ends.

Solderpad 0.51 is an Apache 2.0 derivative with a hardware specific interpretation clause. It is not
copyleft, so these sit beside hashcat's MIT sources without infecting them, on the condition that
the notices travel with the files. They do, in the file headers, and this page names them again. The
full licence text ships in `docs/license_libs/ZTEX_SOLDERPAD_LICENSE.txt`, as the licence asks.

## What is deliberately NOT taken

The ZTEX **firmware kits, host APIs and utilities** are MPL-2.0 or GPL-3. None of them is here and none is needed:

- No microcontroller firmware is built or shipped. The board runs the firmware it came with, "USB-FPGA Module 2.13 default FW", and `ezusb_io.v` is the FPGA side of exactly that firmware's high speed interface, `ezusb_lsi.v` the FPGA side of its low speed one.
- The host side is `src/bridges/fpga/transport_ztex213.c`, written for hashcat against the published vendor request numbers. Those numbers are an interface, documented in the SDK's own reference tables, not code taken from it.

ZTEX 1.15y support uses a different design and protocol. hashcat redistributes John the Ripper's prebuilt `inouttraffic.ihx` and `ztex115y_bcrypt.bit` for that board. The two implementations share only the USB plumbing in `src/bridges/fpga/ztex_usb.c`, parts of which follow John the Ripper's host code, see `src/fpga/bcrypt/PROVENANCE.md`.

## What was written for hashcat

| File | What it does |
|---|---|
| `hcfpga_ztex_top.v` | the shell: clocking, both width conversions, both crossings, the buffer end marker |
| `hcfpga_ztex_regs.v` | the register file behind the low speed channel |
| `hcfpga_ztex_temp.v` | the die temperature, read from the XADC for the register file |
| `hcfpga_ztex_afifo.v` | the gray pointer asynchronous FIFO both crossings are built from |
| `hcfpga_ztex_iface.vh` | the register map, which the bridge repeats |
| `tb_ztex_shell.v` | the shell's own bench, part of `make -C src/fpga sim` |
| `sim/ztex_fx2_model.v` | a model of the FX2 slave FIFO, for that bench |
| `sim/xilinx_prims.v` | simulation only stand-ins for IBUFG, BUFG, MMCME2_BASE and XADC |

`sim/ztex_fx2_model.v` models the outbound endpoint's BUFFERS and its FLAGB, not just its wires: a finite number of 512 byte buffers, a flag that goes low when they are all committed and is late by a parameter, a host that collects at a settable rate, and writes that are thrown away when there is no buffer to take them. That is the path ezusb_io's `resend` exists for, and it is only reachable because the model can run out of buffers. The number of buffers is a parameter because it is a property of the firmware's endpoint configuration rather than of the part.

`sim/xilinx_prims.v` lets the testbench run under Icarus without vendor libraries. It is excluded from synthesis because Vivado supplies the real primitives. The MMCM model measures and divides its input clock to test the shell's clock crossings. The target script checks whether a requested frequency is achievable.
