#!/usr/bin/env bash
#
# Author......: See docs/credits.txt
# License.....: MIT
#

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
CORE="$HERE/bcrypt_core"

IVERILOG="${IVERILOG:-iverilog}"
VVP="${VVP:-vvp}"

WORK="${SIM_WORK:-$HERE/../../build/sim}"

CORE_SRC="$CORE/bcrypt_core.v $CORE/bcrypt_core_c2.v $CORE/fsm.v $CORE/unit.v $CORE/S.v $CORE/P_2x32.v $CORE/addr_regs.v"
DP_SRC="$HERE/hcfpga_top.sv $HERE/hcfpga_feed.v $HERE/hcfpga_feed_group.v $HERE/hcfpga_cores.v $HERE/hcfpga_result_filter.v $HERE/hcfpga_collect.v $HERE/hcfpga_collect_group.v $CORE_SRC"

if [ -e "$WORK" ] && [ ! -f "$WORK/.hcfpga-sim" ]; then
  echo "  $WORK exists and this script did not create it." >&2
  echo "  It would be deleted whole, so this refuses instead. Point SIM_WORK at a path of its own." >&2
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/run"
touch "$WORK/.hcfpga-sim"

cp "$HERE/S_data.txt" "$WORK/"

cd "$WORK/run" || exit 1

PASS=0
FAIL=0

run_one()
{
  local label="$1"; shift
  local gen="$1"; shift
  local tb="$1"; shift
  local src="$1"; shift

  local out="$WORK/run/$label"

  "$IVERILOG" "-$gen" -I "$CORE" -I "$HERE" "$@" -o "$out.vvp" "$tb" $src > "$out.build" 2>&1

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
    tail -20 "$out.log"

    FAIL=$((FAIL + 1))
  fi
}

echo "=== bcrypt core: the two S-box storage styles must compute the same digest ==="

for style in block distributed; do
  for din in 8 32; do
    run_one "tb_core.$style.din$din" g2005 "$CORE/tb_core.v" "$CORE_SRC" \
      -Ptb_core.S_STYLE=\"$style\" -Ptb_core.DIN_BITS="$din"
  done
done

echo
echo "=== datapath: framing, ekid echo, core_id, digest ==="

run_one "tb_datapath.default" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC"

run_one "tb_datapath.mixed_array" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.NUM_CORES_DIST=2

run_one "tb_datapath.collect_group" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.COLLECT_GROUP=2

run_one "tb_datapath.din32_nodump" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.init_batch" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.INIT_BATCH=3

run_one "tb_datapath.init_batch_unreachable" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.INIT_BATCH=64

run_one "tb_datapath.feed_group" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.FEED_GROUP=2

run_one "tb_datapath.feed_shard" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.FEED_SHARD=2 -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.DIN_BITS=32 \
  -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.feed_shard_nopipe" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.FEED_SHARD=2 -Ptb_datapath.FEED_GROUP=0

run_one "tb_datapath.feed_shard_ragged" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.FEED_SHARD=1 -Ptb_datapath.FEED_GROUP=1 -Ptb_datapath.DIN_BITS=32 \
  -Ptb_datapath.COLLECT_GROUP=1 -Ptb_datapath.NUM_CORES_DIST=2 -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.all_on" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.NUM_CORES_DIST=2 -Ptb_datapath.COLLECT_GROUP=1 \
  -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.FEED_SHARD=2 -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.feed_multigroup" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.NUM_CORES=8 -Ptb_datapath.NCAND=16 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.FEED_SHARD=4 -Ptb_datapath.FEED_GROUP=1 -Ptb_datapath.DIN_BITS=32 \
  -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.feed_group_partial" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.FEED_GROUP=3 -Ptb_datapath.CHECK_ALL_CORES=1

run_one "tb_datapath.ypcb_shape" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.NUM_CORES=7 -Ptb_datapath.NCAND=14 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.FEED_SHARD=4 -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.COLLECT_GROUP=3 \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.ypcb_shape_mixed" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.NUM_CORES=7 -Ptb_datapath.NCAND=14 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.FEED_SHARD=4 -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.COLLECT_GROUP=3 \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0 -Ptb_datapath.NUM_CORES_DIST=2

echo
echo "=== expander: the device builds the bcrypt key from the password it was sent ==="

run_one "tb_expand.default" g2005-sv "$HERE/tb_expand.v" "$DP_SRC"

run_one "tb_expand.din32" g2005-sv "$HERE/tb_expand.v" "$DP_SRC" \
  -Ptb_expand.DIN_BITS=32 -Ptb_expand.WITH_DUMP=0

run_one "tb_expand.feed_shard" g2005-sv "$HERE/tb_expand.v" "$DP_SRC" \
  -Ptb_expand.FEED_SHARD=2 -Ptb_expand.FEED_GROUP=2 -Ptb_expand.DIN_BITS=32 \
  -Ptb_expand.COLLECT_GROUP=2 -Ptb_expand.WITH_DUMP=0

run_one "tb_expand.feed_shard_ragged" g2005-sv "$HERE/tb_expand.v" "$DP_SRC" \
  -Ptb_expand.FEED_SHARD=1 -Ptb_expand.FEED_GROUP=1 -Ptb_expand.DIN_BITS=32 \
  -Ptb_expand.COLLECT_GROUP=1 -Ptb_expand.NUM_CORES_DIST=2 -Ptb_expand.WITH_DUMP=0

echo
echo "=== comparator: only a candidate that could be a crack comes back ==="

run_one "tb_cmp.default" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC"

run_one "tb_cmp.all_ones" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.CMP_ALL=1

run_one "tb_cmp.collect_group" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.COLLECT_GROUP=2

run_one "tb_cmp.collect_group_all" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.COLLECT_GROUP=2 -Ptb_cmp.CMP_ALL=1

run_one "tb_cmp.nopad" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.PAD_RECS=1

run_one "tb_cmp.all_on" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.DIN_BITS=32 -Ptb_cmp.NUM_CORES_DIST=2 -Ptb_cmp.COLLECT_GROUP=1 \
  -Ptb_cmp.FEED_GROUP=2 -Ptb_cmp.FEED_SHARD=2 -Ptb_cmp.WITH_DUMP=0

run_one "tb_cmp.no_filter" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.WITH_CMP=0 -Ptb_cmp.CMP_ALL=1

run_one "tb_cmp.backpressure" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.READY_DUTY=1 -Ptb_cmp.COLLECT_GROUP=2 -Ptb_cmp.CMP_ALL=1

run_one "tb_cmp.backpressure_engine_per_core" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.READY_DUTY=1 -Ptb_cmp.COLLECT_GROUP=1 -Ptb_cmp.CMP_ALL=1

run_one "tb_cmp.backpressure_selective" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.READY_DUTY=3 -Ptb_cmp.COLLECT_GROUP=2

run_one "tb_datapath.no_filter" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.WITH_CMP=0

echo
echo "=== heterogeneous: every digest pairs with its own candidate ==="

run_one "tb_hetero.default" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC"

run_one "tb_hetero.feed_shard" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.FEED_SHARD=2 -Ptb_hetero.FEED_GROUP=2 -Ptb_hetero.DIN_BITS=32 \
  -Ptb_hetero.COLLECT_GROUP=2 -Ptb_hetero.WITH_DUMP=0

run_one "tb_hetero.ypcb_shape" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.NUM_CORES=7 -Ptb_hetero.CHECK_ALL_CORES=1 \
  -Ptb_hetero.FEED_SHARD=4 -Ptb_hetero.FEED_GROUP=2 -Ptb_hetero.COLLECT_GROUP=3 \
  -Ptb_hetero.DIN_BITS=32 -Ptb_hetero.WITH_DUMP=0

run_one "tb_hetero.ypcb_shape_mixed" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.NUM_CORES=7 -Ptb_hetero.CHECK_ALL_CORES=1 \
  -Ptb_hetero.FEED_SHARD=4 -Ptb_hetero.FEED_GROUP=2 -Ptb_hetero.COLLECT_GROUP=3 \
  -Ptb_hetero.DIN_BITS=32 -Ptb_hetero.WITH_DUMP=0 -Ptb_hetero.NUM_CORES_DIST=2

run_one "tb_hetero.junk_prefix_even" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.JUNK_WORDS=4

run_one "tb_hetero.junk_prefix_odd" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.JUNK_WORDS=5

run_one "tb_hetero.junk_prefix_odd_shard" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.JUNK_WORDS=7 -Ptb_hetero.FEED_SHARD=2 -Ptb_hetero.FEED_GROUP=2 \
  -Ptb_hetero.DIN_BITS=32 -Ptb_hetero.WITH_DUMP=0

run_one "tb_hetero.all_on" g2005-sv "$HERE/tb_hetero.v" "$DP_SRC" \
  -Ptb_hetero.DIN_BITS=32 -Ptb_hetero.NUM_CORES_DIST=3 -Ptb_hetero.COLLECT_GROUP=2 \
  -Ptb_hetero.FEED_GROUP=2 -Ptb_hetero.FEED_SHARD=2 -Ptb_hetero.WITH_DUMP=0

echo
echo "=== two hash core: two virtual cores per physical core, on a clock twice the fabric's ==="

run_one "tb_core_c2" g2005 "$CORE/tb_core_c2.v" "$CORE_SRC"

run_one "tb_datapath.c2" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.CSLOW=2 -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0 -Ptb_datapath.CHECK_ALL_CORES=1

run_one "tb_datapath.c2_shape" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.CSLOW=2 -Ptb_datapath.NUM_CORES=8 -Ptb_datapath.NCAND=16 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.FEED_SHARD=4 -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.COLLECT_GROUP=2 \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.one_wave_ragged" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.NUM_CORES=7 -Ptb_datapath.NCAND=7 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.FEED_SHARD=4 -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.COLLECT_GROUP=3 \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0

run_one "tb_datapath.c2_one_wave_ragged" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.CSLOW=2 -Ptb_datapath.NUM_CORES=10 -Ptb_datapath.NCAND=10 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.FEED_SHARD=4 -Ptb_datapath.FEED_GROUP=2 -Ptb_datapath.COLLECT_GROUP=2 \
  -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0 -Ptb_datapath.WITH_CMP=0

run_one "tb_datapath.c2_no_filter" g2005-sv "$HERE/tb_datapath.v" "$DP_SRC" \
  -Ptb_datapath.CSLOW=2 -Ptb_datapath.DIN_BITS=32 -Ptb_datapath.WITH_DUMP=0 -Ptb_datapath.CHECK_ALL_CORES=1 \
  -Ptb_datapath.WITH_CMP=0

run_one "tb_cmp.c2" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.CSLOW=2 -Ptb_cmp.DIN_BITS=32 -Ptb_cmp.WITH_DUMP=0

run_one "tb_cmp.c2_backpressure" g2005-sv "$HERE/tb_cmp.v" "$DP_SRC" \
  -Ptb_cmp.CSLOW=2 -Ptb_cmp.DIN_BITS=32 -Ptb_cmp.WITH_DUMP=0 -Ptb_cmp.READY_DUTY=1 \
  -Ptb_cmp.COLLECT_GROUP=2 -Ptb_cmp.CMP_ALL=1

echo
echo "  $PASS passed, $FAIL failed. Logs in $WORK/run."

if [ "$FAIL" -eq 0 ]; then
  echo "  SIM *** PASS ***"
  exit 0
fi

echo "  SIM *** FAIL ***"
exit 1
