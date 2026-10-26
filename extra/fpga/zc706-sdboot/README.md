# ZC706 SD card boot

This boot image configures the ZC706 programmable logic (PL) at power-on. The FPGA is therefore ready when the host enumerates PCIe, without a JTAG load or an additional reboot.

This directory contains the files required to build the boot image. The user-facing procedure is in `docs/hashcat-fpga-setup.md`.

| File | What it is |
|------|------------|
| `fsbl.elf` | Prebuilt first stage boot loader, 181 KB, MIT. See `docs/license_libs/XILINX_FSBL_LICENSE.txt`. |
| `make_bootbin.py` | Packages `fsbl.elf` and a bitstream as `BOOT.BIN`. Requires only Python. |
| `build_fsbl.tcl` | Rebuilds `fsbl.elf` from the sources supplied with Vivado. Not required for normal use. |

**`BOOT.BIN` is generated and is not distributed.** Build it from the bitstream intended for the board. The approximately 13 MB image is specific to that design, so a prebuilt image would not be generally usable. The script writes `BOOT.BIN` to this directory, where `.gitignore` excludes it.

The prebuilt FSBL is independent of the design because it transfers, but does not interpret, the bitstream. One FSBL can therefore serve every design on this board.

## Why an FSBL is required

The Zynq PL cannot load itself from flash. Its processing-system (PS) BootROM starts a first-stage boot loader, which transfers the bitstream through PCAP. Unlike standalone Artix and Kintex devices, Zynq devices require this processor-managed boot path.

Because the FSBL only transfers the bitstream, it is a board-level artifact. The same binary works with every hcfpga design for the ZC706, regardless of algorithm, core count, or clock.

## Why this uses `make_bootbin.py` instead of `bootgen`

Xilinx supplies `bootgen` with Vitis. Requiring Vitis merely to install a published bitstream would make the deployment process depend on the synthesis toolchain.

`make_bootbin.py` writes the boot image directly and requires only Python.

For identical inputs, its output is **byte-for-byte identical** to the deterministic output from `bootgen`. This was verified with three designs and file names of 16, 37, and 48 characters to cover the name-length-dependent layout rules.

## Use

```
make -C src/fpga bcrypt STARTUPCLK=Cclk
./make_bootbin.py src/fpga/bcrypt/build/<build>/gateware/<build>.bit
```

Copy `BOOT.BIN` to the FAT32 partition of an SD card, set SW11 as described below, and power on the board.

**Build the bitstream with `STARTUPCLK=Cclk`**, the current default for every board. `STARTUPCLK` selects the clock used by the PL startup sequence. PCAP configuration does not provide a JTAG clock, so a `JtagClk` bitstream transfers successfully but never asserts DONE. A `Cclk` bitstream works with both PCAP and JTAG.

A `Cclk` build was also verified through JTAG on a ZC706: DONE asserts, and the endpoint enumerates after a reboot.

## SW11, from UG954 v1.4 Table 1-2

The SD boot setting is `0 0 1 1 0`: poles 1, 2, and 5 Down, with poles 3 and 4 **Up**.

UG954 does not label the physical zero direction in this table. Appendix A, Table A-1 identifies the default as "All Down," while Table 1-2, note 1 identifies the default JTAG mode as all zeros. Therefore, Down is 0.

## Reading the boot on UART

UART1 is exposed through the CP2103, usually as `/dev/ttyUSB1`, at 115200 8N1. The other USB port is the Digilent JTAG interface. Because `fsbl.elf` includes `FSBL_DEBUG_INFO`, it reports each boot step.

```
stty -F /dev/ttyUSB1 115200 cs8 -cstopb -parenb -crtscts raw -echo
cat /dev/ttyUSB1
```

After transferring the bitstream, the FSBL checks both DMA completion and the PL DONE signal. The result distinguishes transfer failures from PL startup failures:

| Output | Meaning |
|--------|---------|
| `DMA Done !` then `FPGA Done !` | The PL asserted DONE. Configuration worked. |
| `DMA Done !` then `PCAP_FPGA_DONE_FAIL` | The bitstream reached PCAP intact and the PL never asserted DONE. Wrong STARTUPCLK. |
| A failure before `DMA Done !` | Check the boot image, SD card, and SW11 configuration. |

After `FPGA Done !`, the FSBL prints `IRQ_HANDLER` and enters fallback. This is expected: the image contains no PS application to receive control, and the PL is already configured. SD boot mode does not support fallback, so the process does not loop.
