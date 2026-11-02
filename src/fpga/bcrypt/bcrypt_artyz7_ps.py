#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import argparse
import os
import subprocess
import sys
import time

from hcfpga_abi import fpga_abi_current

BOARD = "artyz7"
PART  = "xc7z020clg400-1"

BOARD_PART = "digilentinc.com:arty-z7-20:part0:1.1"

BOARD_SHAPE = {
    "din_bits":       32,

    "init_batch":     0,

    "num_cores_dist": 0,

    "feed_group":     0,

    "feed_shard":     0,

    "collect_group":  0,

    "no_cmp":         0,
}

def vivado_tcl (args, out_dir, name):
    here     = os.path.dirname (os.path.abspath (__file__))
    gateware = os.path.join (here, "gateware")
    bcrypt   = os.path.join (gateware, "bcrypt")
    core     = os.path.join (bcrypt, "bcrypt_core")
    artyz7   = os.path.join (gateware, "artyz7")
    sources = [
        os.path.join (artyz7, "hcfpga_artyz7_top.v"),
        os.path.join (bcrypt, "hcfpga_top.sv"),
        os.path.join (bcrypt, "hcfpga_feed_group.v"),
        os.path.join (bcrypt, "hcfpga_feed.v"),
        os.path.join (bcrypt, "hcfpga_cores.v"),
        os.path.join (bcrypt, "hcfpga_collect_group.v"),
        os.path.join (bcrypt, "hcfpga_collect.v"),
        os.path.join (bcrypt, "hcfpga_result_filter.v"),
        os.path.join (core,   "bcrypt_core.v"),
        os.path.join (core,   "unit.v"),
        os.path.join (core,   "fsm.v"),
        os.path.join (core,   "addr_regs.v"),
        os.path.join (core,   "P_2x32.v"),
        os.path.join (core,   "S.v"),
    ]
    headers = [
        os.path.join (bcrypt, "bcrypt.vh"),
        os.path.join (bcrypt, "hcfpga_sbox_init.vh"),
        os.path.join (core,   "S_body.vh"),
        os.path.join (here,   "..", "hcfpga_iface.vh"),
    ]
    src_list = " \\\n  ".join ("{%s}" % s for s in sources)
    hdr_list = " \\\n  ".join ("{%s}" % h for h in headers)
    return f"""
create_project -force artyz7 {{{out_dir}}} -part {PART}
set_property board_part {BOARD_PART} [current_project]
add_files -norecurse [list \\
  {src_list} ]
foreach h [list \\
  {hdr_list} ] {{
  if {{[file exists $h]}} {{
    add_files -norecurse $h
    set_property file_type {{Verilog Header}} [get_files $h]
  }}
}}
set_property include_dirs [list {{{bcrypt}}} {{{core}}} {{{os.path.join (here, "..")}}}] [get_filesets sources_1]
update_compile_order -fileset sources_1
create_bd_design "top"
create_bd_cell -type ip -vlnv xilinx.com:ip:processing_system7 ps7
apply_bd_automation -rule xilinx.com:bd_rule:processing_system7 \\
  -config {{make_external "FIXED_IO, DDR" apply_board_preset "1" Master "Disable" Slave "Disable"}} \\
  [get_bd_cells ps7]
# GP0 is the port the PS drives the shell through, and FCLK_CLK0 clocks the whole PL.
#
# DDR stays configured because the PS7 IP requires it, and no part of this design touches it. That is
# deliberate: the application runs from OCM, which skips the DDR section of ps7_init entirely, and
# that section is both the largest and the most board-specific part of it.
set_property -dict [list \\
  CONFIG.PCW_USE_M_AXI_GP0 {{1}} \\
  CONFIG.PCW_EN_CLK0_PORT {{1}} \\
  CONFIG.PCW_FPGA0_PERIPHERAL_FREQMHZ {{{args.sys_clk_mhz}}} ] [get_bd_cells ps7]
create_bd_cell -type module -reference hcfpga_artyz7_top shell
set_property -dict [list \\
  CONFIG.NUM_CORES {{{args.cores}}} \\
  CONFIG.NUM_CORES_DIST {{{args.num_cores_dist}}} \\
  CONFIG.DIN_BITS {{{args.din_bits}}} \\
  CONFIG.INIT_BATCH {{{args.init_batch}}} \\
  CONFIG.FEED_GROUP {{{args.feed_group}}} \\
  CONFIG.FEED_SHARD {{{args.feed_shard}}} \\
  CONFIG.COLLECT_GROUP {{{args.collect_group}}} \\
  CONFIG.WITH_CMP {{{0 if args.no_cmp else 1}}} \\
  CONFIG.WITH_DUMP {{{0 if args.no_dump else 1}}} \\
  CONFIG.CORE_CLK_MHZ {{{args.clk_mhz}}} \\
  CONFIG.BUILD_STAMP {{{args.build_stamp}}} \\
  CONFIG.ABI_VERSION {{{args.abi}}} ] [get_bd_cells shell]
# The AXI slave is INFERRED from the s_axi_* port names rather than declared, so print what Vivado
# actually found. A mis-inference here is silent and only shows up much later as an unconnected pin.
puts "BD_INTF_PINS: [get_bd_intf_pins shell/*]"
apply_bd_automation -rule xilinx.com:bd_rule:axi4 \\
  -config [list Clk_master {{Auto}} Clk_slave {{Auto}} Clk_xbar {{Auto}} \\
                Master {{/ps7/M_AXI_GP0}} Slave {{/shell/s_axi}} \\
                ddr_seg {{Auto}} intc_ip {{New AXI SmartConnect}} master_apm {{0}}] \\
  [get_bd_intf_pins shell/s_axi]
assign_bd_address
validate_bd_design
save_bd_design
set bd [get_files top.bd]
make_wrapper -files $bd -top
add_files -norecurse [make_wrapper -files $bd -top -force]

set_property top top_wrapper [current_fileset]
update_compile_order -fileset sources_1
{"" if args.place_directive == "Default" else
 'set_property STEPS.PLACE_DESIGN.ARGS.DIRECTIVE ' + args.place_directive + ' [get_runs impl_1]'}
launch_runs impl_1 -to_step write_bitstream -jobs {args.threads}
wait_on_run impl_1
open_run impl_1

# A raw bitstream alongside the .bit, and it is the raw one the bridge loads.
#
# A .bit wraps the same configuration data in keyed fields holding a design name, a part name, a date
# and a time. None of that reaches the device. Writing the raw form here spares the bridge a parser
# for it.
write_bitstream -force -bin_file {{{out_dir}/gateware/{name}}}
report_utilization    -file {{{out_dir}/{name}_utilization.rpt}}
report_timing_summary -file {{{out_dir}/{name}_timing.rpt}}
set wns [get_property SLACK [get_timing_paths -delay_type max]]

puts "HCFPGA_BUILD_DONE cores={args.cores} clk={args.sys_clk_mhz} WNS=$wns"
# A bcrypt core that misses timing computes wrong digests rather than stopping, so the bitstream is
# removed and the build fails.
if {{$wns < 0}} {{
  file delete -force {{{out_dir}/gateware/{name}.bit}} {{{out_dir}/gateware/{name}.bin}}
  puts "HCFPGA_TIMING_FAILED the design does not meet timing at this clock"
  exit 1
}}
"""
def main ():
    p = argparse.ArgumentParser (description = "hcfpga bcrypt on Arty Z7-20")
    p.add_argument ("--build",  action = "store_true", help = "synthesise, implement and write a bitstream")
    p.add_argument ("--load",   action = "store_true", help = "not supported here, see the note it prints")
    p.add_argument ("--cores",         type = int, default = 68)
    p.add_argument ("--sys-clk-freq",  type = float, default = 91e6)
    p.add_argument ("--threads",       type = int, default = 8)
    p.add_argument ("--abi",           type = int, default = fpga_abi_current (), help = "Wire version stamped into the identity. Taken from FPGA_ABI_CURRENT in the bridge header, the same value src/fpga/Makefile reads. The shell reports it at its ABI register, and the bridge programs the board again when it does not match.")
    p.add_argument ("--startup-clk",   default = "Cclk")
    p.add_argument ("--din-bits",       type = int, default = BOARD_SHAPE["din_bits"])
    p.add_argument ("--init-batch",     type = int, default = BOARD_SHAPE["init_batch"])
    p.add_argument ("--num-cores-dist", type = int, default = BOARD_SHAPE["num_cores_dist"], help = "How many cores keep their S-boxes in distributed RAM. 0 on this part: it runs out of LUTs and block RAM at almost the same core count, so there is nothing to trade.")
    p.add_argument ("--feed-group",     type = int, default = BOARD_SHAPE["feed_group"])
    p.add_argument ("--feed-shard",     type = int, default = BOARD_SHAPE["feed_shard"])
    p.add_argument ("--collect-group",  type = int, default = BOARD_SHAPE["collect_group"])
    p.add_argument ("--no-cmp",         action = "store_true")
    p.add_argument ("--no-dump",        action = "store_true")
    p.add_argument ("--place-directive", type = str, default = "Default", help = "Vivado placer directive, set on the implementation run. Default is what every published bitstream for this board was built with, so a plain build reproduces it exactly. The value lands in the build directory name so a sweep cannot overwrite itself.")
    args = p.parse_args ()
    if args.load:
        print ("  This script does not program the board.")
        print ("  This board's PL is loaded by hashcat over JTAG, along with the PS application, at")
        print ("  the start of a run that uses the board and does not find both already running.")
        print ("  See docs/hashcat-fpga-setup.md, section 'Arty Z7-20'.")
        return 0
    if args.build == False:
        p.print_help ()

        return 1

    args.sys_clk_mhz = args.sys_clk_freq / 1e6
    print (f"  building {BOARD}: {args.cores} cores, {args.sys_clk_mhz:.3f} MHz requested")
    print (f"  the PS7 will round that to the nearest ratio of its dividers")
    mhz = int (round (args.sys_clk_mhz))
    suffix = ""
    if args.feed_group     != 0: suffix += "_fg%d" % args.feed_group
    if args.no_dump        != 0: suffix += "_nodump"
    if args.no_cmp         != 0: suffix += "_nocmp"
    if args.din_bits       != 8: suffix += "_din%d" % args.din_bits
    if args.num_cores_dist != 0: suffix += "_d%d"  % args.num_cores_dist
    if args.feed_shard     != 0: suffix += "_fs%d" % args.feed_shard
    if args.collect_group  != 0: suffix += "_cg%d" % args.collect_group
    if args.init_batch     != 0: suffix += "_ib%d" % args.init_batch
    if args.place_directive != "Default": suffix += "_p%s" % args.place_directive
    name = "bcrypt_%s_ps_c%d_%dmhz_%s%s" % (BOARD, args.cores, mhz, args.startup_clk.lower (), suffix)
    out_dir = os.path.join (os.path.dirname (os.path.abspath (__file__)), "build", name)
    os.makedirs (os.path.join (out_dir, "gateware"), exist_ok = True)
    args.clk_mhz     = mhz
    args.build_stamp = int (time.time ())

    tcl_path = os.path.join (out_dir, "build.tcl")
    with open (tcl_path, "w") as f:
        f.write (vivado_tcl (args, out_dir, name))

    rc = subprocess.call (["vivado", "-mode", "batch", "-nojournal", "-notrace",
                           "-log", os.path.join (out_dir, "vivado.log"),
                           "-source", tcl_path])
    return rc
if __name__ == "__main__":
    sys.exit (main ())
