#!/usr/bin/env bash
#
# Author......: See docs/credits.txt
# License.....: MIT
#

set -u

source "${VIVADO_SETTINGS:-/opt/Xilinx/Vivado/2026.1/settings64.sh}"
export LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}

WHICH=${1:-both}
DIN_BITS=${2:-8}
FEED_GROUP=${3:-0}
WITH_DUMP=${4:-1}

RTL=$(cd "$(dirname "$0")" && pwd)
CORE="$RTL/bcrypt_core"

run_one()
{
  local tb="$1"

  local work="${SIM_WORK:-$RTL/../../build/corrsim}/$tb"

  if [ -e "$work" ] && [ ! -f "$work/.hcfpga-sim" ]; then
    echo "  $work exists and this script did not create it, so this refuses to delete it." >&2
    return 1
  fi

  rm -rf "$work"
  mkdir -p "$work"
  touch "$work/.hcfpga-sim"

  cd "$work" || return 1

  xvlog --relax -i "$RTL" -i "$CORE" \
    "$RTL/$tb.v" "$RTL/hcfpga_top.sv" "$RTL/hcfpga_feed.v" "$RTL/hcfpga_feed_group.v" \
    "$RTL/hcfpga_cores.v" "$RTL/hcfpga_result_filter.v" "$RTL/hcfpga_collect.v" "$RTL/hcfpga_collect_group.v" \
    "$CORE/bcrypt_core.v" "$CORE/fsm.v" "$CORE/unit.v" "$CORE/S.v" \
    "$CORE/P_2x32.v" "$CORE/addr_regs.v" > xvlog.log 2>&1 \
    || { echo "$tb: xvlog FAIL"; tail -25 xvlog.log; return 1; }

  xelab "$tb" -s "sim_$tb" --debug off \
    -generic_top "DIN_BITS=$DIN_BITS" \
    -generic_top "FEED_GROUP=$FEED_GROUP" \
    -generic_top "WITH_DUMP=$WITH_DUMP" > xelab.log 2>&1 \
    || { echo "$tb: xelab FAIL"; tail -25 xelab.log; return 1; }

  xsim "sim_$tb" --runall > xsim.log 2>&1

  echo "--- $tb (DIN_BITS=$DIN_BITS FEED_GROUP=$FEED_GROUP WITH_DUMP=$WITH_DUMP)"
  grep -iE "PASS|FAIL|bad|mismatch|ERROR" xsim.log | tail -15
}

case "$WHICH" in
  both) run_one tb_datapath; run_one tb_hetero ;;
  *)    run_one "$WHICH" ;;
esac
