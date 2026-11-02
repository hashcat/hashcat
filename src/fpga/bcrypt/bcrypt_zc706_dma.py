#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import os
import argparse
import datetime

from migen import *

from litex.gen import *
from litex.gen import LiteXContext

from litex_boards.platforms import xilinx_zc706

from litex.soc.interconnect     import stream
from litex.soc.integration.soc_core import *
from litex.soc.integration.builder  import *

from litex.soc.cores.clock import S7MMCM
from litex.soc.cores.dna   import S7DNA
from litex.soc.cores.led   import LedChaser
from litex.soc.cores.xadc  import S7SystemMonitor

from litepcie.phy.s7pciephy import S7PCIEPHY
from litepcie.software      import generate_litepcie_software_headers

from gateware.bcrypt_dma_wrapper import BcryptDmaWrapper

from hcfpga_abi import fpga_abi_current
from hcfpga_litepcie import pcie_set_class, pcie_clock_cuts, add_debug_jtagbone, vivado_build_args, clock_mhz

BOARD = "zc706"

BOARD_SHAPE = {
    "din_bits":       32,

    "init_batch":     0,

    "num_cores_dist": 0,

    "feed_group":     32,

    "feed_shard":     64,

    "collect_group":  30,

    "no_cmp":         0,
}

class _CRG(LiteXModule):
    def __init__(self, platform, sys_clk_freq, cslow=1):
        self.rst    = Signal()
        self.cd_sys = ClockDomain()

        self.pll = pll = S7MMCM(speedgrade=-2)
        self.comb += pll.reset.eq(self.rst)
        pll.register_clkin(platform.request("clk200"), 200e6)
        pll.create_clkout(cd=self.cd_sys, freq=sys_clk_freq, reset_buf="bufg")

        if cslow == 2:
            self.cd_core = ClockDomain()
            pll.create_clkout(self.cd_core, 2 * sys_clk_freq)
        else:
            platform.add_false_path_constraints(self.cd_sys.clk, pll.clkin)

class BcryptSoC(SoCMini):
    def __init__(self, sys_clk_freq=125e6, with_jtagbone=False, num_cores=1, startup_clock="JtagClk", with_led=True, pcie_lanes=1, feed_group=0, feed_shard=0, collect_group=0, init_batch=0, num_cores_dist=0, with_dump=1, with_cmp=1, din_bits=32, abi=1, cslow=1):
        platform = xilinx_zc706.Platform()

        self.crg = _CRG(platform, sys_clk_freq, cslow)

        stamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        SoCMini.__init__(self, platform, sys_clk_freq,
            ident         = f"hcfpga/1;board={BOARD};algo=bcrypt;cores={num_cores};clk={int(sys_clk_freq/1e6)};abi={abi};build={stamp}",
            ident_version = False,
        )

        if with_jtagbone == True:
            add_debug_jtagbone(self, platform, self.crg.cd_sys)

        pcie_data_width = 64 if pcie_lanes == 1 else 128

        self.pcie_phy = S7PCIEPHY(platform, platform.request(f"pcie_x{pcie_lanes}"),
            data_width = pcie_data_width,
            bar0_size  = 0x10_0000,
            pclk_mux_direct_from_mmcm = True)
        pcie_set_class(self.pcie_phy)
        self.add_pcie(phy=self.pcie_phy, ndmas=1, address_width=64)

        if cslow == 2:
            platform.toolchain.pre_placement_commands.append("create_generated_clock -name sys_clk [get_pins MMCME2_ADV/CLKOUT0]")
            platform.toolchain.pre_placement_commands.append("create_generated_clock -name core_clk [get_pins MMCME2_ADV/CLKOUT1]")

            platform.toolchain.pre_placement_commands.append("set_false_path -from [get_clocks sys_clk] -to [get_clocks clk200_p]")
            platform.toolchain.pre_placement_commands.append("set_false_path -from [get_clocks clk200_p] -to [get_clocks sys_clk]")
        else:
            platform.add_period_constraint(self.crg.cd_sys.clk, 1e9/sys_clk_freq)

        pcie_clock_cuts(platform)

        platform.toolchain.pre_placement_commands.append("set_clock_uncertainty 0.500 [get_clocks sys_clk]")
        platform.toolchain.pre_routing_commands.append("set_clock_uncertainty 0 [get_clocks sys_clk]")

        platform.toolchain.bitstream_commands.append("set_property BITSTREAM.CONFIG.UNUSEDPIN PULLNONE [current_design]")

        platform.toolchain.bitstream_commands.append("set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]")
        platform.toolchain.bitstream_commands.append(f"set_property BITSTREAM.STARTUP.STARTUPCLK {startup_clock} [current_design]")

        if with_led:
            self.leds = LedChaser(pads=platform.request_all("user_led"), sys_clk_freq=sys_clk_freq)

        self.xadc = S7SystemMonitor()

        self.csr.add("dna", n=9)

        self.dna = S7DNA(clk_divider=8)
        self.dna.add_timing_constraints(platform, sys_clk_freq, self.crg.cd_sys.clk)

        self.bcrypt = BcryptDmaWrapper(platform, num_cores=num_cores,
            num_cores_dist=num_cores_dist, din_bits=din_bits, feed_group=feed_group,
            feed_shard=feed_shard,
            collect_group=collect_group, init_batch=init_batch, with_dump=with_dump, with_cmp=with_cmp,
            cslow=cslow)
        self.bcrypt.add_hdl_sources()

        dw = self.pcie_dma0.data_width

        self.dma_down = stream.Converter(dw, 32, reverse=False)
        self.comb += [
            self.pcie_dma0.source.connect(self.dma_down.sink),
            self.dma_down.source.connect(self.bcrypt.sink),
        ]

        self.dma_up = stream.Converter(8, dw, reverse=False)
        self.comb += [
            self.bcrypt.source.connect(self.dma_up.sink),
            self.dma_up.source.connect(self.pcie_dma0.sink),
        ]

def main():
    parser = argparse.ArgumentParser(description="hcfpga bcrypt on Xilinx ZC706.")
    parser.add_argument("--build", action="store_true", help="Build the bitstream.")
    parser.add_argument("--load",  action="store_true", help="Load the bitstream via openFPGALoader.")
    parser.add_argument("--cores",        type=int,   default=1,     help="Number of bcrypt cores.")
    parser.add_argument("--no-dump",      action="store_true",       help="Omit the unfinished S state dump logic, whose muxes affect the Feistel critical path.")
    parser.add_argument("--no-cmp",       action="store_true",       help="Omit the per-core comparator to save about 30 LUTs per core. Every candidate then returns to the host.")
    parser.add_argument("--din-bits",     type=int,   default=BOARD_SHAPE["din_bits"],     help="Feeder-to-core bus width, 8 or 32 bits. A 32-bit bus shortens initialization broadcasts.")
    parser.add_argument("--feed-group",   type=int,   default=BOARD_SHAPE["feed_group"],   help="Cores per feeder fanout group. An extra pipeline register per group splits the long broadcast route. Zero means NO fanout pipeline at all rather than one group: hcfpga_cores.v takes its nopipe branch, NBUS becomes NSH, and each core takes its feeder engine's bus directly.")
    parser.add_argument("--feed-shard",   type=int,   default=BOARD_SHAPE["feed_shard"],   help="Cores per feeder engine. Must be a multiple of --feed-group. Zero uses one engine.")
    parser.add_argument("--collect-group", type=int,  default=BOARD_SHAPE["collect_group"], help="Cores per collector engine. Zero uses one engine over the whole array.")
    parser.add_argument("--num-cores-dist", type=int, default=BOARD_SHAPE["num_cores_dist"], help="Cores whose S-boxes use distributed RAM. Zero uses block RAM for every core.")
    parser.add_argument("--init-batch",   type=int,   default=BOARD_SHAPE["init_batch"],   help="Ready cores required to start an initialization broadcast. Zero starts immediately.")
    parser.add_argument("--sys-clk-freq", type=float, default=125e6, help="System clock (Hz).")
    parser.add_argument("--threads",      type=int,   default=os.cpu_count(), help="Vivado threads.")
    parser.add_argument("--with-jtagbone", action="store_true", help="Include JTAGBone for CSR access through litex_server --jtag. Excluded from published builds.")
    parser.add_argument("--place-directive", type=str, default="Explore", help="Vivado placer directive. The default matches the published bitstream. The choice is included in the build directory name.")
    parser.add_argument("--abi",          type=int,   default=fpga_abi_current(), help="Wire ABI version, stamped into the bitstream identity and refused by the bridge when it does not match. Read from FPGA_ABI_CURRENT in src/bridges/fpga/hcfpga.h, which the Makefile reads too, so a direct invocation builds what hashcat accepts.")
    parser.add_argument("--startup-clk",  type=str,   default="JtagClk", choices=["JtagClk", "Cclk"], help="PL startup clock. JtagClk to load over JTAG, Cclk to boot from the SD card. This script defaults to JtagClk; the published bitstream is built with Cclk.")
    parser.add_argument("--cslow",        type=int,   default=1, choices=[1, 2], help="2 builds the array from two hash cores on a second clock at twice --sys-clk-freq. --cores then counts virtual cores.")
    parser.add_argument("--pcie-lanes",   type=int,   default=1, choices=[1, 4], help="PCIe link width. Published builds use x1. The board supports up to x4.")
    args = parser.parse_args()

    mhz  = clock_mhz(args.sys_clk_freq)

    fg_suffix = "" if args.feed_group == 0 else f"_fg{args.feed_group}"

    nd_suffix = "_nodump" if args.no_dump == True else ""
    nc_suffix = "_nocmp"  if args.no_cmp  == True else ""

    db_suffix = "" if args.din_bits == 8 else f"_din{args.din_bits}"

    fs_suffix = "" if args.feed_shard    == 0 else f"_fs{args.feed_shard}"
    cg_suffix = "" if args.collect_group  == 0 else f"_cg{args.collect_group}"
    ds_suffix = "" if args.num_cores_dist == 0 else f"_d{args.num_cores_dist}"
    ib_suffix = "" if args.init_batch     == 0 else f"_ib{args.init_batch}"

    pd_suffix = "" if args.place_directive == "Explore" else f"_p{args.place_directive}"

    if args.cslow == 2: pd_suffix += "_cs2"

    lanes_suffix = f"_x{args.pcie_lanes}"

    name = f"bcrypt_{BOARD}_dma_c{args.cores}_{mhz}mhz_{args.startup_clk.lower()}{lanes_suffix}{fg_suffix}{nd_suffix}{nc_suffix}{db_suffix}{ds_suffix}{fs_suffix}{cg_suffix}{ib_suffix}{pd_suffix}"

    soc = BcryptSoC(
        sys_clk_freq = args.sys_clk_freq,
        num_cores    = args.cores,
        feed_group   = args.feed_group,
        feed_shard   = args.feed_shard,
        with_dump    = 0 if args.no_dump else 1,
        with_cmp     = 0 if args.no_cmp  else 1,
        din_bits     = args.din_bits,
        collect_group  = args.collect_group,
        num_cores_dist = args.num_cores_dist,
        init_batch     = args.init_batch,
        startup_clock  = args.startup_clk,
        abi          = args.abi,
        pcie_lanes   = args.pcie_lanes,
        with_jtagbone = args.with_jtagbone,
        cslow        = args.cslow,
    )

    builder = Builder(soc, output_dir=os.path.join("build", name))
    builder.build(build_name=name, run=args.build, **vivado_build_args(args.threads, args.place_directive))

    hdr_dir = os.path.join("software", "kernel", BOARD)

    os.makedirs(hdr_dir, exist_ok=True)
    generate_litepcie_software_headers(soc, hdr_dir)

    if args.load:
        prog = soc.platform.create_programmer("openfpgaloader")
        prog.load_bitstream(builder.get_bitstream_filename(mode="sram"))

if __name__ == "__main__":
    main()
