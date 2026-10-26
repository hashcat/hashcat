#!/usr/bin/env bash
#
# Author......: See docs/credits.txt
# License.....: MIT
#

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
GATEWARE="$(cd "$HERE/.." && pwd)"
BCRYPT="$GATEWARE/bcrypt"
CORE="$BCRYPT/bcrypt_core"
IFACE="$(cd "$GATEWARE/.." && pwd)"

IVERILOG="${IVERILOG:-iverilog}"
VVP="${VVP:-vvp}"

WORK="${SIM_WORK:-$GATEWARE/../build/sim}"

CORE_SRC="$CORE/bcrypt_core.v $CORE/fsm.v $CORE/unit.v $CORE/S.v $CORE/P_2x32.v $CORE/addr_regs.v"
DP_SRC="$BCRYPT/hcfpga_top.sv $BCRYPT/hcfpga_feed.v $BCRYPT/hcfpga_feed_group.v $BCRYPT/hcfpga_cores.v $BCRYPT/hcfpga_result_filter.v $BCRYPT/hcfpga_collect.v $BCRYPT/hcfpga_collect_group.v $CORE_SRC"
SHELL_SRC="$HERE/hcfpga_ztex_top.v $HERE/hcfpga_ztex_regs.v $HERE/hcfpga_ztex_temp.v $HERE/hcfpga_ztex_afifo.v $HERE/ezusb_io.v $HERE/ezusb_lsi.v $HERE/sim/xilinx_prims.v $HERE/sim/ztex_fx2_model.v"

created=1

if [ -e "$WORK" ]; then
  created=0
fi

mkdir -p "$WORK/run"

if [ "$created" -eq 1 ]; then
  touch "$WORK/.hcfpga-sim"
fi

cp "$BCRYPT/S_data.txt" "$WORK/"

cd "$WORK/run" || exit 1

PASS=0
FAIL=0

run_one()
{
  local label="$1"; shift

  local out="$WORK/run/$label"

  "$IVERILOG" -g2005-sv -I "$HERE" -I "$BCRYPT" -I "$CORE" -I "$IFACE" "$@" \
    -o "$out.vvp" "$HERE/tb_ztex_shell.v" $SHELL_SRC $DP_SRC > "$out.build" 2>&1

  if [ $? -ne 0 ]; then
    printf '  %-34s BUILD FAIL\n' "$label"
    tail -20 "$out.build"

    FAIL=$((FAIL + 1))
    return
  fi

  "$VVP" "$out.vvp" > "$out.log" 2>&1

  local verdict

  verdict="$(grep -c 'OVERALL \*\*\* PASS \*\*\*' "$out.log")"

  if [ "$verdict" = "1" ]; then
    printf '  %-34s PASS\n' "$label"

    PASS=$((PASS + 1))
  else
    printf '  %-34s FAIL\n' "$label"
    tail -25 "$out.log"

    FAIL=$((FAIL + 1))
  fi
}

echo "=== ztex fx2 shell: lsi registers, width conversion, cdc, framing, flush, digest ==="

run_one "tb_ztex_shell.default"

run_one "tb_ztex_shell.125mhz" \
  -Ptb_ztex_shell.CORE_CLK_MHZ=125 -Ptb_ztex_shell.MMCM_MULT_MILLI=15625 -Ptb_ztex_shell.MMCM_OUTDIV_MILLI=6000

run_one "tb_ztex_shell.board_shape" \
  -Ptb_ztex_shell.NUM_CORES_DIST=2 -Ptb_ztex_shell.WITH_DUMP=0

run_one "tb_ztex_shell.board_geometry" \
  -Ptb_ztex_shell.NUM_CORES=24 -Ptb_ztex_shell.NUM_CORES_DIST=4 -Ptb_ztex_shell.WITH_DUMP=0 \
  -Ptb_ztex_shell.NCAND=48

run_one "tb_ztex_shell.ragged_feed" \
  -Ptb_ztex_shell.NUM_CORES=24 -Ptb_ztex_shell.NUM_CORES_DIST=4 -Ptb_ztex_shell.WITH_DUMP=0 \
  -Ptb_ztex_shell.NCAND=24 -Ptb_ztex_shell.FEED_BURST=4 -Ptb_ztex_shell.FEED_GAP_CYC=1200

echo
echo "  $PASS passed, $FAIL failed. Logs in $WORK/run."

if [ "${HCFPGA_ZTEX_STALL:-0}" != "0" ]; then
  echo
  echo "=== outside the gate: backpressure and a late inbound flag. These are expected to FAIL. ==="

  STALL="-Ptb_ztex_shell.NUM_CORES=24 -Ptb_ztex_shell.NUM_CORES_DIST=4 -Ptb_ztex_shell.WITH_DUMP=0"
  STALL="$STALL -Ptb_ztex_shell.NCAND=48 -Ptb_ztex_shell.TIMEOUT_NS=4000000"

  run_one "tb_ztex_shell.stall_lat2" $STALL -Ptb_ztex_shell.HOST_DRAIN_CYC=40000
  run_one "tb_ztex_shell.stall_lat1" $STALL -Ptb_ztex_shell.HOST_DRAIN_CYC=40000 -Ptb_ztex_shell.FLAG_LATENCY=1
  run_one "tb_ztex_shell.stall_lat0" $STALL -Ptb_ztex_shell.HOST_DRAIN_CYC=40000 -Ptb_ztex_shell.FLAG_LATENCY=0
  run_one "tb_ztex_shell.host_away"  $STALL -Ptb_ztex_shell.OUT_BUFS=1 -Ptb_ztex_shell.HOST_STOP_AT=1 -Ptb_ztex_shell.HOST_STOP_CYC=200000

  run_one "tb_ztex_shell.late_flaga" \
    -Ptb_ztex_shell.NUM_CORES=24 -Ptb_ztex_shell.NUM_CORES_DIST=4 -Ptb_ztex_shell.WITH_DUMP=0 \
    -Ptb_ztex_shell.NCAND=48 -Ptb_ztex_shell.FLAGA_LATENCY=2

  echo "  the three lines to read in each log are the packet list, the dropped word count and the pktend gate."

  exit 1
fi

if [ "$FAIL" -eq 0 ]; then
  echo "  ZTEX SIM *** PASS ***"
  exit 0
fi

echo "  ZTEX SIM *** FAIL ***"
exit 1
