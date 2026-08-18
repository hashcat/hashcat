#!/usr/bin/env bash
#
# Run tools/test.sh against an ASan-instrumented hashcat, one hash type at a
# time. Unlike tools/compute_sanitizer/, which checks the CUDA kernels, this
# checks hashcat's own host C under a real end-to-end workload: allocation
# handling, the parsers, backend bookkeeping.
#
# The real GPU kernels still run, just unchecked.
#
# Usage:
#   make DEBUG=2 -j$(nproc)
#   tools/asan/gpu_sweep.sh                 # all hash types
#   tools/asan/gpu_sweep.sh --from 6050     # resume from a hash type
#   tools/asan/gpu_sweep.sh --modes "0 100 1000"
#
set -u

OUT=${OUT:-./asan-gpu-sweep}
FROM=0
MODES=""

while [ $# -gt 0 ]; do
  case "$1" in
    --from)  FROM="$2"; shift 2 ;;
    --modes) MODES="$2"; shift 2 ;;
    *) echo "usage: $0 [--from <mode>] [--modes \"<m> <m> ...\"]" >&2; exit 2 ;;
  esac
done

if [ ! -x ./hashcat ]; then
  echo "error: ./hashcat not found -- run 'make DEBUG=2 -j\$(nproc)' first" >&2
  exit 2
fi

if [ -z "$MODES" ]; then
  MODES=$(ls tools/test_modules/*.pm | sed -E 's/.*m0*([0-9]+)\.pm/\1/' \
          | sort -n -u | awk -v f="$FROM" '$1>=f')
fi

mkdir -p "$OUT/logs"
LOG="$OUT/sweep.log"
: > "$LOG"

# protect_shadow_gap=0 is REQUIRED. ASan maps its shadow gap PROT_NONE, and
# CUDA's unified virtual addressing needs that range: without it cuInit()
# fails with "out of memory" and hashcat reports "No OpenCL, HIP or CUDA
# compatible platform found" -- which looks like a missing driver and is not.
# use_sigaltstack=0 for the same reason it is set in sweep.sh and repro.sh:
# under a clang runtime older than glibc 2.34 the sanitizer aborts before
# main(), which would make every mode here look "clean" without running.
export ASAN_OPTIONS="protect_shadow_gap=0:detect_leaks=0:halt_on_error=0:use_sigaltstack=0:log_path=$OUT/logs/asan"

# A DEBUG=2 SANITIZE=address,undefined tree emits UBSan checks too, and those
# print to stderr rather than log_path -- they land in $OUT/m<mode>.out. Set
# the options so they carry a stack trace and do not halt the run.
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:use_sigaltstack=0"

for mode in $MODES; do
  [ -z "$mode" ] && continue

  start=$(date +%s)
  # < /dev/null matters: test.sh reads stdin, and without this it swallows the
  # rest of the mode list and the sweep silently ends after one iteration.
  timeout 1800 ./tools/test.sh -m "$mode" -a all -V 1 -t single -f \
    > "$OUT/m${mode}.out" 2>&1 < /dev/null
  rc=$?
  dur=$(( $(date +%s) - start ))

  errs=$(cat "$OUT"/logs/asan.* 2>/dev/null | grep -c "ERROR: AddressSanitizer")

  # UBSan does not use log_path -- it prints "file.c:12:34: runtime error: ..."
  # to stderr, which lands in m<mode>.out. Checking only the ASan logs would
  # silently discard every UBSan finding on a SANITIZE=address,undefined tree.
  uerrs=$(grep -c "runtime error:" "$OUT/m${mode}.out" 2>/dev/null || echo 0)

  if [ "${errs:-0}" -gt 0 ] || [ "${uerrs:-0}" -gt 0 ]; then
    echo "m${mode}: *** ${errs} ASAN / ${uerrs} UBSAN ERRORS *** (${dur}s, rc=$rc)" | tee -a "$LOG"
    grep -h -oP "ERROR: AddressSanitizer: \K.*" "$OUT"/logs/asan.* 2>/dev/null \
      | sort -u | head -5 | sed 's/^/    /' | tee -a "$LOG"
    grep -hoP "^[^ ]+:\d+:\d+: runtime error: .*" "$OUT/m${mode}.out" 2>/dev/null \
      | sort -u | head -5 | sed 's/^/    /' | tee -a "$LOG"
    mkdir -p "$OUT/findings/m${mode}"
    mv "$OUT"/logs/asan.* "$OUT/findings/m${mode}/" 2>/dev/null
    [ "${uerrs:-0}" -gt 0 ] && cp "$OUT/m${mode}.out" "$OUT/findings/m${mode}/" 2>/dev/null
  elif [ "$rc" = "124" ]; then
    echo "m${mode}: TIMEOUT (1800s)" | tee -a "$LOG"
  else
    echo "m${mode}: clean (${dur}s)" >> "$LOG"
  fi

  rm -f "$OUT"/logs/asan.* 2>/dev/null
done

echo "=== ASAN GPU SWEEP DONE ===" | tee -a "$LOG"
grep -c ": clean"     "$LOG" | sed 's/^/clean modes:         /' | tee -a "$LOG"
grep -c "ASAN ERRORS" "$LOG" | sed 's/^/modes with findings: /' | tee -a "$LOG"
