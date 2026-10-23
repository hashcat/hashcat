#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

PCIE_CLASS_CODE = 0x0B80

PCIE_CLASS_MENU_BASE = "Encryption/Decryption_controllers"
PCIE_CLASS_MENU_SUB  = "Other_en/decryption"

def pcie_set_class (phy):
  base_code = "%02X" % ((PCIE_CLASS_CODE >> 8) & 0xff)
  sub_code  = "%02X" % ((PCIE_CLASS_CODE >> 0) & 0xff)

  config = {}

  config["Base_Class_Menu"]          = PCIE_CLASS_MENU_BASE
  config["Sub_Class_Interface_Menu"] = PCIE_CLASS_MENU_SUB
  config["Class_Code_Base"]          = base_code
  config["Class_Code_Sub"]           = sub_code

  phy.update_config (config)

PCIE_PHY_CLOCK_OUTPUTS = (0, 1, 3)

def _tcl_braced (name):
  return "{{" + name + "}}"

def pcie_clock_cuts (platform):
  phy_clocks = [_tcl_braced ("*s7pciephy_clkout%d" % n) for n in PCIE_PHY_CLOCK_OUTPUTS]

  pairs = [(clk, _tcl_braced ("sys_clk")) for clk in phy_clocks]

  pairs.append ((phy_clocks[0], phy_clocks[1]))

  for a, b in pairs:
    for src, dst in ((a, b), (b, a)):
      cmd = "set ca [get_clocks -quiet %s]; set cb [get_clocks -quiet %s]; " % (src, dst)

      cmd += "if {{[llength $ca] && [llength $cb]}} {{ set_false_path -from $ca -to $cb }}"

      platform.toolchain.pre_placement_commands.append (cmd)

JTAGBONE_TCK_HZ = 20e6

def add_debug_jtagbone (soc, platform, sys_cd):
  soc.add_jtagbone ()

  jtag_clk = soc.jtagbone_phy.cd_jtag.clk

  platform.add_period_constraint (jtag_clk, 1e9 / JTAGBONE_TCK_HZ)

  platform.add_false_path_constraints (jtag_clk, sys_cd.clk)

VIVADO_DIRECTIVES = {
  "vivado_synth_directive"               : "PerformanceOptimized",
  "vivado_post_place_phys_opt_directive" : "AggressiveExplore",
  "vivado_route_directive"               : "AggressiveExplore",
  "vivado_post_route_phys_opt_directive" : "AggressiveExplore",
}

def vivado_build_args (threads, place_directive):
  args = dict (VIVADO_DIRECTIVES)

  args["vivado_max_threads"]     = threads
  args["vivado_place_directive"] = place_directive

  return args

def clock_mhz (freq_hz):
  mhz = int (freq_hz // 1e6)

  return mhz
