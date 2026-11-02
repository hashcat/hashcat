# bcrypt FPGA provenance

The Blowfish and bcrypt compute core in this design is John the Ripper's ZTEX bcrypt core, written by Denis Burykin. hashcat uses it under its own permissive license and has modified it. Every file taken from it keeps its original header verbatim, and each modified file adds a notice under that header pointing here. This page lists every change.

The rest of the design was written for hashcat: the feeder, the core array, the collector, the result filter, the framing, the board shells and the host interface. `README.md` describes it.

## Origin

Upstream is **openwall/john**, `src/ztex/fpga-bcrypt/bcrypt/` and its `bcrypt_core/` directory. The files are Copyright (c) 2016 or 2016,2019 Denis Burykin, as each header states, and carry the same permissive terms: "Redistribution and use in source and binary forms, with or without modification, are permitted."

## Files taken from John the Ripper

| File | Change |
|---|---|
| `gateware/bcrypt/bcrypt_core/S_data.txt` | none, byte identical |
| `gateware/bcrypt/S_data.txt` | none, byte identical. A second copy, the one the benches read as `../S_data.txt` |
| `gateware/bcrypt/bcrypt_core/{addr_regs,P_2x32}.v` | the include path |
| `gateware/bcrypt/bcrypt_core/unit.v` | the include path, the S storage parameter, the state dump ports |
| `gateware/bcrypt/bcrypt_core/S.v` | rewritten as a wrapper that picks block or distributed RAM, see below. It keeps upstream's header and nothing of its logic |
| `gateware/bcrypt/bcrypt_core/S_body.vh` | upstream `S.v`'s logic: the module name and RAM style from macros, and the state dump read path |
| `gateware/bcrypt/bcrypt_core/bcrypt_core.v` | the include path, the S storage parameter, a 32 bit input bus, the startup and framing reset, the state dump |
| `gateware/bcrypt/bcrypt_core/fsm.v` | the include path, the reset, a microcode change at MC[0], the state dump |
| `gateware/bcrypt/bcrypt.vh` | `SIMULATION` enabled, and the state dump's opcodes and jump condition |
| `gateware/bcrypt/bcrypt_core/bcrypt_core_c2.v` | derived from the core files above, two hashes per core, see below |

All of these but `addr_regs.v`, `P_2x32.v` and the two `S_data.txt` were converted from CRLF to LF line endings. `S_body.vh` drops upstream's `timescale` line, because `S.v` carries it.

### The include path

The files write `` `include "bcrypt.vh" `` where upstream writes `` `include "../bcrypt.vh" ``. It is the same file, found through an include path rather than a relative directory. The flat form also resolves in a flat directory, which is what the Vitis packager produces: it copies HDL into the packaged IP without the tree it came from.

### `SIMULATION`

`bcrypt.vh` defines `SIMULATION`, which upstream leaves commented out. The name is upstream's and misleads: it selects the real, synthesisable core in `bcrypt_core.v` instead of an empty stub.

### The S-box storage split

Upstream `S.v` declares the four banks with no storage attribute and lets synthesis choose. Here the array chooses per core, because a core's S-boxes cost either 2 block RAM tiles or a large share of LUTs, and an array of one kind runs out of one pool with the other half empty. See `NUM_CORES_DIST` in `gateware/bcrypt/hcfpga_cores.v`.

A synthesis attribute takes a literal, and passing a parameter to one relies on a Vivado extension that other tools may drop. So `S.v` is now a wrapper whose `generate` picks one of two sibling modules, and both include `S_body.vh`. The logic exists once, and only the attribute differs. `S_STYLE` carries the choice through `bcrypt_core.v` and `unit.v`.

### The 32 bit input bus

Upstream's `din` is 8 bits wide and a word takes four cycles. `bcrypt_core.v` takes `DIN_BITS` 8 or 32. At 32 a word arrives in two beats, lanes 0 to 2 and then lane 3, so `wr_b2` still leads `wr_b3` by one cycle and the microcode's end of region detection keeps its timing. At 8 the core behaves exactly as upstream. Every published board uses 32.

### The reset

`bcrypt_core.v` and `fsm.v` take a synchronous `rst` that forces the control state to the power-on values. At startup that matches what Xilinx GSR does to the device, so simulation starts from the same state.

The same input is the framing reset, which the host asserts after a failed batch while cores are mid job. The PD write pointer has no reset, so a reset core kept the pointer of the interrupted job and wrote its next data batch out of place. It then either never left loading and was lost until the fabric was reconfigured, or returned a wrong digest. **MC[0] now loads the PD write pointer** (`PDAR_LD_ADDR_EK` where upstream has `PDAR_X_`). In normal operation that is a no-op, because every job already ends with the same load. `fsm.v` explains it at MC[0].

### The state dump

Added so that a core can hand its EksBlowfish state back to the host, which would let a long job be split across several launches. The ZC706, Enigma X1 and Arty Z7 build it, the ZTEX 2.13 and YPCB leave it out with `no_dump`, and the host does not use it.

It is inert unless `mode_dump` is asserted. With the signal low the core computes exactly what upstream computes.

| File | Change |
|---|---|
| `S_body.vh`, `S.v` | `dump_en`, `dump_entry`, `dump_bank` inputs. With `dump_en` the four banks are all read at `dump_entry` and `out` returns the selected one raw, instead of the round function `S3 + (S2 ^ (S1 + S0))`. The normal read channel cannot yield an individual word |
| `unit.v` | passes those three signals through |
| `bcrypt_core.v` | the `mode_dump` input, a walk counter, a new jump condition (#15) and an end of walk term added to the existing condition #4 |
| `fsm.v` | the dump sequence in MC[83] to MC[89] and MC[64], and a branch to it at MC[67] where the core would emit a digest |
| `bcrypt.vh` | `E_DUMP_CNT_RST`, `E_DUMP_CNT_INC`, `JMP_mode_dump`. `E_DUMP_CNT_INC` is defined and unused |

**`mode_dump` must not be asserted while a core is computing.** It steers the S read address, so a core running with it high reads the wrong entries and produces a wrong digest.

`bcrypt_core/tb_core.v` checks the digest path in the merge gate. Run by hand with `+dump=1`, it walks S out and compares it against the state `bcrypt_core/bcrypt_ref.py` predicts.

Apart from the changes above, the Blowfish datapath, the S-box and P-array logic, the round logic, the crypt state machine and the key expansion are upstream's. The core's I/O protocol is not documented upstream. What this design relies on is written up in `README.md`, and `bcrypt_core/tb_core.v` asserts it.

### Two hashes per core

`bcrypt_core_c2.v` is derived from `bcrypt_core.v`, `fsm.v`, `unit.v`, `P_2x32.v`, `S_body.vh` and `addr_regs.v`, and carries Denis Burykin's header followed by a notice that the derivation is hashcat's. It runs two independent hashes in one core, interleaved cycle by cycle, which C-slows the core by two:

- every register becomes a two stage chain, and every memory takes the virtual core number as its top address bit, so PD and PN are 64 deep and each S bank 512.
- a register splits the round loop after the first adder, `U = S0 + S1` beside copies of `S2` and `S3`.
- a zero flag per virtual core replaces the reset and hold of the S read register.
- the collision exception's re-read moves from MC[81] to MC[82], directly before its use, because the shared read latch cannot keep one virtual core's value across the other's cycle. That needs a new PN address opcode, `PNAR_LD_ADDR_P_PLUS1`.
- the state dump is not carried, and `mode_cmp` is gone.

Everything else in its microcode is `fsm.v`'s, the MC[0] change included. Its header explains the design. The YPCB ships it, see `CSLOW` in `src/fpga/Makefile`.

## Other material derived from John the Ripper

These are written for hashcat, but follow John the Ripper's design closely enough to name.

| Where | Derived from |
|---|---|
| `gateware/bcrypt/hcfpga_feed.v`, the init image layout | upstream `bcrypt_data.v`: P at word 0, 6 reserved words, the "OrpheanBeholderScryDoubt" magic at word 24, S at word 30, and the data batch layout. The values are the public Blowfish and bcrypt constants. The layout is the core's interface |
| `src/bridges/fpga/transport_ztex115y.c` | the host side of John the Ripper's ZTEX 1.15y support, by Denis Burykin: the clock table (verbatim from `src/ztex/ez-usb/inouttraffic.c`), the firmware upload (a port of `ztex.c`), the packet checksum and constants (`pkt_comm`), the link limits (`ztex_bcrypt.c`), and the vendor requests, reimplemented from the protocol |
| `src/bridges/fpga/ztex_usb.c` | `ztex_swap_bits` and the high speed configuration sequence, from John the Ripper's `ztex.c` |
| `src/bridges/bridge_fpga_bcrypt.c` | the comparator and word generator wire formats of the 1.15y design, from `pkt_comm/cmp_config.c` and `word_gen.c` |

The ZTEX 1.15y bitstream and firmware are John the Ripper's own files, redistributed unchanged. See `deps/ztex-bitstreams/README.md` and `docs/license_libs/ZTEX_BITSTREAM_LICENSE.txt`.

## Other third party material

| Where | What |
|---|---|
| `gateware/ztex_fx2/ezusb_io.v`, `ezusb_lsi.v` | ZTEX GmbH, unmodified, Solderpad Hardware License 0.51, see `gateware/ztex_fx2/PROVENANCE.md` and `docs/license_libs/ZTEX_SOLDERPAD_LICENSE.txt` |
| `software/user/liblitepcie/` | LiteX's `liblitepcie` (BSD-2-Clause, EnjoyDigital), the user space library `dma_ek_test` links against |
| `deps/litepcie-2026.08/` | the LitePCIe kernel driver, built with the 5 patches in `src/fpga/driver/patches/` |
| `extra/fpga/zc706-sdboot/fsbl.elf` | Xilinx's first stage boot loader, a 181 KB binary kept in the tree as an exception so that users need no Vivado installation to boot a ZC706 from SD. `build_fsbl.tcl` beside it rebuilds it, see `docs/license_libs/XILINX_FSBL_LICENSE.txt` |

## Written for hashcat

| File | Notes |
|---|---|
| `gateware/bcrypt/hcfpga_feed.v` | record intake, gated on a free core in a sharded array, the key expansion, the init ROM broadcast, dispatch and the gapless byte streamer |
| `gateware/bcrypt/hcfpga_feed_group.v` | several feeder engines over slices of the array, one record stream |
| `gateware/bcrypt/hcfpga_cores.v` | the core array, the byte lane glue and the two hash pairs |
| `gateware/bcrypt/hcfpga_result_filter.v` | the per core comparator |
| `gateware/bcrypt/hcfpga_collect.v`, `hcfpga_collect_group.v` | the result collector and its engines |
| `gateware/bcrypt/hcfpga_top.sv` | the datapath top |
| `gateware/bcrypt/hcfpga_sbox_init.vh`, `gen_sbox_init.py` | the S constants as literal assignments into the init image, and their generator |
| `gateware/bcrypt_dma_wrapper.py` | the LiteX wrapper |
| `gateware/ztex_fx2/`, `gateware/artyz7/` | the ZTEX 2.13 and Arty Z7 shells |
| `bcrypt_*_dma.py`, `bcrypt_ztex213_usb.py`, `bcrypt_artyz7_ps.py`, `hcfpga_abi.py`, `hcfpga_litepcie.py` | the board targets, the shared ABI reader and the settings the PCIe targets share |
| `hcfpga_iface.vh`, `software/user/hcfpga_iface.h` | the frame contract between host and gateware |
| `ps_app/`, `software/user/dma_ek_test.c` | the Arty Z7 application and the PCIe self test |
| testbenches and scripts in `gateware/bcrypt/` and `bcrypt_core/` | `tb_core`, `tb_core_c2`, `tb_datapath`, `tb_hetero`, `tb_cmp`, `tb_expand`, `tb_feed_throughput`, their vector generators, `bcrypt_ref.py` and the `run_*.sh` scripts. `run_iverilog_sim.sh` is the merge gate |

## Toolchain

LiteX, litex-boards and LitePCIe, openFPGALoader to program boards, Vivado to synthesise and iverilog to simulate. The tools are used unmodified. The LitePCIe kernel driver is built with the patches named above.
