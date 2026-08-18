#!/usr/bin/env bash
#
# Run every module's host-side parser under AddressSanitizer, with mutations.
# No GPU, no backend, no CUDA driver.
#
# Usage:
#   tools/asan/build.sh
#   tools/asan/sweep.sh [results-dir]
#
# Takes roughly 25 minutes for all 594 modules.

set -u

HARNESS=${HARNESS:-./asan_harness}
OUT=${1:-./asan-sweep}

if [ ! -x "$HARNESS" ]; then
  echo "error: $HARNESS not found -- run tools/asan/build.sh first" >&2
  exit 2
fi

mkdir -p "$OUT"
LOG="$OUT/sweep.log"
: > "$LOG"

# halt_on_error=0 keeps going after the first report, so a module with two
# distinct defects shows both rather than hiding the second behind the first.
# detect_leaks=0 because hashcat does not free everything by design.
# use_sigaltstack=0: harmless under the gcc runtime this script builds against
# by default, but mandatory under a clang runtime older than glibc 2.34, where
# SIGSTKSZ stopped being a compile-time constant and the runtime tries to
# allocate a 0-byte alternate signal stack. Without it the sanitizer aborts
# before main() and the sweep records a clean pass for every module -- a
# false all-clear, the one failure direction that must never be silent.
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:use_sigaltstack=0:log_path=$OUT/tmp_asan"

# UBSan reports look nothing like ASan's: one "file.c:12:34: runtime error: ..."
# line per finding, printed to stderr, and by default it keeps going without a
# stack trace. Ask for the trace, and let it continue so one module's first
# finding does not hide the rest.
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:use_sigaltstack=0"

for so in modules/module_*.so; do
  base=$(basename "$so" .so)
  mode=$((10#${base#module_}))

  rm -f "$OUT"/tmp_asan.* 2>/dev/null

  timeout 600 "$HARNESS" "$so" "$mode" --mutate > "$OUT/m${mode}.out" 2>&1
  rc=$?

  # fatal errors land on the harness's own stderr, recoverable ones in log_path
  errs=$(cat "$OUT"/tmp_asan.* 2>/dev/null | grep -c "ERROR: AddressSanitizer")
  inline=$(grep -c "ERROR: AddressSanitizer" "$OUT/m${mode}.out" 2>/dev/null)
  # UBSan findings, deduplicated: the same runtime error inside a loop prints
  # once per iteration and would otherwise dominate the count
  ub=$({ cat "$OUT"/tmp_asan.* 2>/dev/null; cat "$OUT/m${mode}.out"; } \
       | grep -oP "^[^ ]+: runtime error: .*" | sort -u | wc -l)
  total=$(( ${errs:-0} + ${inline:-0} + ${ub:-0} ))

  if [ "$rc" = "124" ]; then
    echo "m${mode}: TIMEOUT (600s)" | tee -a "$LOG"
  elif [ "$total" -gt 0 ]; then
    echo "m${mode}: *** ${total} SANITIZER ERRORS *** (asan=$(( ${errs:-0} + ${inline:-0} )) ubsan=${ub:-0})" | tee -a "$LOG"
    { cat "$OUT"/tmp_asan.* 2>/dev/null; cat "$OUT/m${mode}.out"; } \
      | grep -oP "ERROR: AddressSanitizer: \K[a-z-]+" | sort -u \
      | sed 's/^/    /' | tee -a "$LOG"
    { cat "$OUT"/tmp_asan.* 2>/dev/null; cat "$OUT/m${mode}.out"; } \
      | grep -oP "runtime error: \K.*" | sed 's/[0-9]\+/N/g' | sort -u | head -4 \
      | sed 's/^/    ubsan: /' | tee -a "$LOG"
    { cat "$OUT"/tmp_asan.* 2>/dev/null; cat "$OUT/m${mode}.out"; } \
      | grep -oP "#[0-9]+ 0x[0-9a-f]+ in \K[a-z_0-9]+ [^ ]+\.c:[0-9]+" | sort -u \
      | head -4 | sed 's/^/      /' | tee -a "$LOG"
    mkdir -p "$OUT/findings/m${mode}"
    cat "$OUT"/tmp_asan.* > "$OUT/findings/m${mode}/asan.log" 2>/dev/null
    cp "$OUT/m${mode}.out" "$OUT/findings/m${mode}/" 2>/dev/null
  else
    echo "m${mode}: clean" >> "$LOG"
  fi
done

rm -f "$OUT"/tmp_asan.* 2>/dev/null

echo "=== ASAN PARSER SWEEP DONE ===" | tee -a "$LOG"
grep -c ": clean$"      "$LOG" | sed 's/^/clean modes:       /' | tee -a "$LOG"
grep -c "SANITIZER ERRORS" "$LOG" | sed 's/^/modes with errors: /' | tee -a "$LOG"
grep -c "TIMEOUT"       "$LOG" | sed 's/^/timeouts:          /' | tee -a "$LOG"
echo "per-finding logs: $OUT/findings/"
