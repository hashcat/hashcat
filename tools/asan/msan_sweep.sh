#!/usr/bin/env bash
#
# Run every module's parser under MemorySanitizer, looking for a parser that
# READS a field it never wrote -- an uninitialized-value bug. That is a
# different class from what sweep.sh (ASan/UBSan) finds: not an out-of-bounds
# access, but a value the kernel then hashes, which makes it a correctness
# risk as much as a memory-safety one.
#
# MSan cannot share a process with ASan, so this cannot reuse the dlopen-based
# asan_harness. It uses repro.sh, which compiles the module straight into an
# MSan-instrumented harness and links a PLAIN (uninstrumented) core.
#
# IMPORTANT -- this UNDER-reports by construction. Only the harness, the named
# module and whatever EXTRA names are instrumented; uninitialized values that
# originate inside the uninstrumented core are invisible. A clean result here
# means "no finding in the instrumented part", never "no finding".
#
# IT ALSO OVER-REPORTS, and that half bites harder. MSan tracks initialization
# only in instrumented code. When an UNINSTRUMENTED core function writes into a
# caller-owned buffer, MSan never sees the write, so the caller's next read of
# that buffer is reported as use-of-uninitialized-value -- a false positive
# with a completely plausible-looking stack trace.
#
# Confirmed instance: every module calling b58dec() (m28501/2/5/6, m30901/2/5/6)
# reports `pubkey` uninitialized, because b58dec lives in libhashcat.so.7. It
# writes all 64 bytes on success; instrument it and the finding vanishes.
#
# So THIS SWEEP IS A SCREEN, NOT A VERDICT. Two stages:
#
#   1. this script -- fast, narrow instrumentation, flags candidates
#   2. per candidate, re-run with the core widely instrumented; a finding that
#      survives is real, one that disappears was a core artifact:
#
#      CC=clang-11 TOOL=msan OUT=/tmp/msan-wide \
#      EXTRA="src/convert.c src/shared.c $(ls src/emu_*.c | tr '\n' ' ')" \
#        tools/asan/repro.sh <mode> --mutate
#
# Stage 2 is kept out of the sweep itself on purpose: it adds ~30 translation
# units per module, which is affordable for a handful of candidates and not
# for all 593.
#
# Usage: tools/asan/msan_sweep.sh [results-dir]
set -u

OUT=${1:-./msan-sweep}
CC_BIN=${CC:-clang-11}
EXTRA_SRC=${EXTRA:-src/convert.c}

[ -f src/modules/module_00000.c ] || { echo "run from hashcat source root" >&2; exit 2; }
[ -f ./libhashcat.so.7 ] || { echo "need ./libhashcat.so.7" >&2; exit 2; }
if nm -D ./libhashcat.so.7 2>/dev/null | grep -q __asan; then
  echo "error: core is ASan-instrumented; MSan needs a plain core" >&2; exit 2
fi

mkdir -p "$OUT"
LOG="$OUT/sweep.log"
: > "$LOG"

modes=$(ls src/modules/module_*.c | sed -E 's/.*module_0*([0-9]+)\.c/\1/' | sort -n -u)
total=$(echo "$modes" | wc -w)
echo "=== MSAN PARSER SWEEP: $total modules ===" | tee -a "$LOG"

for mode in $modes; do
  out=$(CC="$CC_BIN" TOOL=msan EXTRA="$EXTRA_SRC" OUT="$OUT/bin" \
        timeout 300 ./tools/asan/repro.sh "$mode" --mutate 2>&1)
  rc=$?

  if echo "$out" | grep -q "MemorySanitizer:"; then
    n=$(echo "$out" | grep -c "MemorySanitizer:")
    echo "m${mode}: *** ${n} MSAN ***" | tee -a "$LOG"
    echo "$out" | grep -oP "MemorySanitizer: \K.*" | sort -u | head -3 | sed 's/^/    /' | tee -a "$LOG"
    mkdir -p "$OUT/findings/m${mode}"
    printf '%s\n' "$out" > "$OUT/findings/m${mode}/msan.out"
  elif [ "$rc" = "124" ]; then
    echo "m${mode}: TIMEOUT" | tee -a "$LOG"
  elif echo "$out" | grep -qE "error:|No such file"; then
    echo "m${mode}: BUILD-FAIL" >> "$LOG"
  else
    echo "m${mode}: clean" >> "$LOG"
  fi
  rm -rf "$OUT/bin" 2>/dev/null
done

echo "=== MSAN PARSER SWEEP DONE ===" | tee -a "$LOG"
# Anchor these to the per-mode line format. A bare grep -c "MSAN" also counts
# this script's own banner lines and overstates the finding count.
grep -c ": clean"                "$LOG" | sed 's/^/clean modes:      /' | tee -a "$LOG"
grep -cE "^m[0-9]+: \*\*\* .*MSAN" "$LOG" | sed 's/^/modes with MSan:  /' | tee -a "$LOG"
grep -cE "^m[0-9]+: TIMEOUT"     "$LOG" | sed 's/^/timeouts:         /' | tee -a "$LOG"
grep -cE "^m[0-9]+: BUILD-FAIL"  "$LOG" | sed 's/^/build failures:   /' | tee -a "$LOG"
echo "NOTE: these are STAGE-1 CANDIDATES, not confirmed bugs. See header." | tee -a "$LOG"
