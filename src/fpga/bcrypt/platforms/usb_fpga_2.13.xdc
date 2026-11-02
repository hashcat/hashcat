#
# Author......: See docs/credits.txt
# License.....: MIT
#

create_clock -name fxclk_in -period 20.833 [get_ports fxclk_in]
set_property PACKAGE_PIN P15 [get_ports fxclk_in]
set_property IOSTANDARD LVCMOS33 [get_ports fxclk_in]

create_clock -name ifclk_in -period 20.833 [get_ports ifclk_in]
set_property PACKAGE_PIN P17 [get_ports ifclk_in]
set_property IOSTANDARD LVCMOS33 [get_ports ifclk_in]

set_property PACKAGE_PIN T10 [get_ports reset]
set_property IOSTANDARD LVCMOS33 [get_ports reset]

set_property PACKAGE_PIN M16 [get_ports {fd[0]}]
set_property PACKAGE_PIN L16 [get_ports {fd[1]}]
set_property PACKAGE_PIN L14 [get_ports {fd[2]}]
set_property PACKAGE_PIN M14 [get_ports {fd[3]}]
set_property PACKAGE_PIN L18 [get_ports {fd[4]}]
set_property PACKAGE_PIN M18 [get_ports {fd[5]}]
set_property PACKAGE_PIN R12 [get_ports {fd[6]}]
set_property PACKAGE_PIN R13 [get_ports {fd[7]}]
set_property PACKAGE_PIN T9  [get_ports {fd[8]}]
set_property PACKAGE_PIN V10 [get_ports {fd[9]}]
set_property PACKAGE_PIN U11 [get_ports {fd[10]}]
set_property PACKAGE_PIN V11 [get_ports {fd[11]}]
set_property PACKAGE_PIN V12 [get_ports {fd[12]}]
set_property PACKAGE_PIN U13 [get_ports {fd[13]}]
set_property PACKAGE_PIN U14 [get_ports {fd[14]}]
set_property PACKAGE_PIN V14 [get_ports {fd[15]}]
set_property IOSTANDARD LVCMOS33 [get_ports {fd[*]}]
set_property DRIVE 4 [get_ports {fd[*]}]

set_property PACKAGE_PIN N16 [get_ports FLAGA]
set_property PACKAGE_PIN N15 [get_ports FLAGB]
set_property PACKAGE_PIN T14 [get_ports SLOE]
set_property PACKAGE_PIN R11 [get_ports FIFOADDR0]
set_property PACKAGE_PIN T11 [get_ports FIFOADDR1]
set_property PACKAGE_PIN R10 [get_ports PKTEND]
set_property PACKAGE_PIN V16 [get_ports SLRD]
set_property PACKAGE_PIN U16 [get_ports SLWR]
set_property IOSTANDARD LVCMOS33 [get_ports {FLAGA FLAGB SLOE FIFOADDR0 FIFOADDR1 PKTEND SLRD SLWR}]

set_property PACKAGE_PIN R17 [get_ports lsi_miso]
set_property PACKAGE_PIN R18 [get_ports lsi_mosi]
set_property PACKAGE_PIN P18 [get_ports lsi_clk]
set_property PACKAGE_PIN P14 [get_ports lsi_stop]
set_property IOSTANDARD LVCMOS33 [get_ports {lsi_miso lsi_mosi lsi_clk lsi_stop}]
set_property DRIVE 4 [get_ports lsi_miso]

set_input_delay  -clock ifclk_in -min 0  [get_ports {FLAGA FLAGB fd[*]}]
set_input_delay  -clock ifclk_in -max 14 [get_ports {FLAGA FLAGB fd[*]}]

set_output_delay -clock ifclk_in -min 0  [get_ports {SLRD SLWR SLOE PKTEND FIFOADDR0 FIFOADDR1 fd[*]}]
set_output_delay -clock ifclk_in -max 5  [get_ports {SLRD SLWR SLOE PKTEND FIFOADDR0 FIFOADDR1 fd[*]}]

set_false_path -from [get_ports {reset lsi_clk lsi_mosi lsi_stop}]
set_false_path -to   [get_ports lsi_miso]

set_clock_groups -asynchronous \
  -group [get_clocks -include_generated_clocks ifclk_in] \
  -group [get_clocks -include_generated_clocks fxclk_in]

set_property CONFIG_VOLTAGE 3.3 [current_design]
set_property CFGBVS VCCO [current_design]
set_property BITSTREAM.GENERAL.COMPRESS true [current_design]
set_property BITSTREAM.CONFIG.UNUSEDPIN PULLUP [current_design]
