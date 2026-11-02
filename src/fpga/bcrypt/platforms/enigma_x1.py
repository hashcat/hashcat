#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

from litex.build.generic_platform import *
from litex.build.xilinx           import Xilinx7SeriesPlatform
from litex.build.openfpgaloader   import OpenFPGALoader

_io = [
    ("clk100", 0, Pins("J19"), IOStandard("LVCMOS33")),

    ("user_led", 0, Pins("G21"), IOStandard("LVCMOS33")),
    ("user_led", 1, Pins("G22"), IOStandard("LVCMOS33")),

    ("user_sw", 0, Pins("F19"), IOStandard("LVCMOS33")),
    ("user_sw", 1, Pins("F20"), IOStandard("LVCMOS33")),

    ("pcie_x1", 0,
        Subsignal("rst_n", Pins("C13"), IOStandard("LVCMOS33"), Misc("PULLUP=TRUE")),
        Subsignal("clk_p", Pins("F10")),
        Subsignal("clk_n", Pins("E10")),
        Subsignal("rx_p",  Pins("D9")),
        Subsignal("rx_n",  Pins("C9")),
        Subsignal("tx_p",  Pins("D7")),
        Subsignal("tx_n",  Pins("C7")),
    ),

    ("pcie_present", 0, Pins("A13"), IOStandard("LVCMOS33")),
    ("pcie_wake_n",  0, Pins("B13"), IOStandard("LVCMOS33")),

    ("usb_fifo_clock", 0, Pins("K18"), IOStandard("LVCMOS33")),
    ("usb_fifo", 0,
        Subsignal("data", Pins(
            "H20 H22 J21 J22 K21 K22 L21 N18",
            "M18 L20 L19 M20 M22 M21 N22 N20",
            "P15 T21 R16 T18 U17 U20 U21 V22",
            "W22 W21 Y22 Y21 AB22 AA21 AB21 AA20")),
        Subsignal("be",     Pins("V20 V19 W20 AB20")),
        Subsignal("rxf_n",  Pins("AA18")),
        Subsignal("txe_n",  Pins("AA19")),
        Subsignal("rd_n",   Pins("P16")),
        Subsignal("wr_n",   Pins("W19")),
        Subsignal("oe_n",   Pins("W17")),
        Subsignal("siwu_n", Pins("AB18")),
        Subsignal("rst_n",  Pins("N13")),
        IOStandard("LVCMOS33"),
        Misc("SLEW=FAST"),
    ),
]

class Platform(Xilinx7SeriesPlatform):
    default_clk_name   = "clk100"
    default_clk_period = 1e9/100e6

    def __init__(self, toolchain="vivado"):
        device = "xc7a75t-fgg484-2"

        Xilinx7SeriesPlatform.__init__(self, device, _io, toolchain=toolchain)

        self.add_platform_command("set_property CFGBVS VCCO [current_design]")
        self.add_platform_command("set_property CONFIG_VOLTAGE 3.3 [current_design]")

    def create_programmer(self):
        return OpenFPGALoader(fpga_part="xc7a75t", cable="ft232", freq=6e6)

    def do_finalize(self, fragment):
        Xilinx7SeriesPlatform.do_finalize(self, fragment)
        self.add_period_constraint(self.lookup_request(self.default_clk_name, loose=True), self.default_clk_period)
