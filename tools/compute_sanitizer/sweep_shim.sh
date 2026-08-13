#!/usr/bin/env bash
##
## Drop-in replacement for a plain `./hashcat` invocation, used by
## tools/test.sh --compute-sanitizer and tools/test_edge.sh --compute-sanitizer
## via their BIN/HC_BIN indirection. Wraps the real hashcat invocation in
## `run.py exec --sweep` (transparent stdout/stderr/exit-code passthrough,
## so the calling script's own pass/fail parsing is unaffected) and routes
## results into the sweep's own results directory.
##
## Required env: SANITIZER_SWEEP_DIR (results directory for this sweep run)
## Optional env: SANITIZER_SWEEP_TOOL (memcheck|racecheck|synccheck|initcheck, default memcheck)
##            SANITIZER_SWEEP_PADDING (bytes of redzone after each device allocation, default 128 --
##                                     see run.py exec --padding)
##

set -u

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${TDIR}/../.." && pwd )"

if [ -z "${SANITIZER_SWEEP_DIR:-}" ]; then
  echo "sweep_shim.sh: SANITIZER_SWEEP_DIR must be set (internal error -- not meant to be invoked directly)" >&2
  exit 2
fi

SLUG="t$(date +%s%N)-$$"

TOOL_FLAG=(--tool "${SANITIZER_SWEEP_TOOL:-memcheck}")
PADDING_FLAG=(--padding "${SANITIZER_SWEEP_PADDING:-128}")

exec python3 "${TDIR}/run.py" exec "${SLUG}" "${TOOL_FLAG[@]}" "${PADDING_FLAG[@]}" --sweep \
     --results-dir "${SANITIZER_SWEEP_DIR}" \
     -- "${REPO_ROOT}/hashcat-sanitizer" "$@"
