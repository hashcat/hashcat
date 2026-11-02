#!/usr/bin/env bash
#
# Author......: See docs/credits.txt
# License.....: MIT
#

set -u

source "${VIVADO_SETTINGS:-/opt/Xilinx/Vivado/2026.1/settings64.sh}"
export LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}

RTL=$(cd "$(dirname "$0")" && pwd)
SD="$RTL/../S_data.txt"

BASE=${SIM_WORK:-$RTL/../../../build/coresim}

rm -rf "$BASE"; mkdir -p "$BASE/run"; cp "$SD" "$BASE/S_data.txt"; cd "$BASE/run" || exit 1
xvlog --relax -i "$RTL" -i "$RTL/.." "$RTL"/tb_core.v "$RTL"/bcrypt_core.v "$RTL"/fsm.v "$RTL"/unit.v "$RTL"/S.v "$RTL"/P_2x32.v "$RTL"/addr_regs.v > xvlog.log 2>&1 || { echo "xvlog FAIL"; tail -20 xvlog.log; exit 1; }
xelab -debug off tb_core -s tb -generic_top "DIN_BITS=${DIN_BITS:-8}" > xelab.log 2>&1 || { echo "xelab FAIL"; tail -20 xelab.log; exit 1; }
xsim tb --runall ${XSIM_ARGS:-} > xsim.log 2>&1
grep -iE "\[tb\]" xsim.log | tail -8
