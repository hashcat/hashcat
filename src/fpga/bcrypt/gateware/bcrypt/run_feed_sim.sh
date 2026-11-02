#!/usr/bin/env bash
#
# Author......: See docs/credits.txt
# License.....: MIT
#

set -u

source "${VIVADO_SETTINGS:-/opt/Xilinx/Vivado/2026.1/settings64.sh}"
export LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}

CORES=${1:-16}
ITERS=${2:-1}
DIN_BITS=${DIN_BITS:-8}
WARMUP=${WARMUP:-64}
MEASURE=${MEASURE:-200}

FEED_GROUP=${FEED_GROUP:-0}
FEED_SHARD=${FEED_SHARD:-0}
COLLECT_GROUP=${COLLECT_GROUP:-0}
NUM_CORES_DIST=${NUM_CORES_DIST:-0}
INIT_BATCH=${INIT_BATCH:-0}
WITH_DUMP=${WITH_DUMP:-1}

RTL=$(cd "$(dirname "$0")" && pwd)
CORE="$RTL/bcrypt_core"

WORK=${SIM_WORK:-$RTL/../../build/feedsim}

if [ -e "$WORK" ] && [ ! -f "$WORK/.hcfpga-sim" ]; then
  echo "  $WORK exists and this script did not create it." >&2
  echo "  It would be deleted whole, so this refuses instead. Point SIM_WORK at a path of its own." >&2
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"
touch "$WORK/.hcfpga-sim"

cd "$WORK"

xvlog --relax -i "$RTL" -i "$CORE" \
  "$RTL/tb_feed_throughput.v" "$RTL/hcfpga_top.sv" "$RTL/hcfpga_feed.v" \
  "$RTL/hcfpga_feed_group.v" "$RTL/hcfpga_cores.v" "$RTL/hcfpga_result_filter.v" \
  "$RTL/hcfpga_collect.v" "$RTL/hcfpga_collect_group.v" \
  "$CORE/bcrypt_core.v" "$CORE/fsm.v" "$CORE/unit.v" "$CORE/S.v" \
  "$CORE/P_2x32.v" "$CORE/addr_regs.v" > xvlog.log 2>&1 \
  || { echo "xvlog FAIL"; tail -25 xvlog.log; exit 1; }

xelab tb_feed_throughput -s tbf --debug off \
  -generic_top "NUM_CORES=$CORES" -generic_top "ITERS=$ITERS" \
  -generic_top "DIN_BITS=$DIN_BITS" \
  -generic_top "FEED_GROUP=$FEED_GROUP" -generic_top "FEED_SHARD=$FEED_SHARD" \
  -generic_top "COLLECT_GROUP=$COLLECT_GROUP" -generic_top "NUM_CORES_DIST=$NUM_CORES_DIST" \
  -generic_top "INIT_BATCH=$INIT_BATCH" -generic_top "WITH_DUMP=$WITH_DUMP" \
  -generic_top "WARMUP=$WARMUP" -generic_top "MEASURE=$MEASURE" > xelab.log 2>&1 \
  || { echo "xelab FAIL"; tail -25 xelab.log; exit 1; }

xsim tbf --runall > xsim.log 2>&1

grep -E "^\[tb\]" xsim.log
