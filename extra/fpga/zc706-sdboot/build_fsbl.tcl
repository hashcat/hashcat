#
# Author......: See docs/credits.txt
# License.....: MIT
#

set here [file dirname [file normalize [info script]]]

if {[info exists ::env(ZC706_XSA)]} {
  set xsa $::env(ZC706_XSA)
} elseif {[info exists ::env(XILINX_VIVADO)]} {
  set xsa $::env(XILINX_VIVADO)/data/embeddedsw/lib/fixed_hwplatforms/zc706.xsa
} else {
  puts "Set XILINX_VIVADO (source settings64.sh) or point ZC706_XSA at zc706.xsa"
  exit 1
}

if {[file exists $xsa] == 0} {
  puts "zc706.xsa not found: $xsa"
  exit 1
}

setws $here/build

platform create -name zc706_ps -hw $xsa -proc ps7_cortexa9_0 -os standalone
bsp setlib -name xilffs
platform generate

app create -name fsbl -platform zc706_ps -template "Zynq FSBL"
app config -name fsbl define-compiler-symbols FSBL_DEBUG_INFO
app build -name fsbl

puts "Built $here/build/fsbl/Debug/fsbl.elf"
puts "Run arm-none-eabi-strip before replacing the supplied fsbl.elf"

exit
