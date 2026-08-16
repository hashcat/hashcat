#!/usr/bin/env bash
#
# Reproduce a single parser finding, with the module compiled straight into the
# harness instead of dlopen()ed.
#
# Use this when you want a small self-contained binary for one module -- it
# needs only a `make DEBUG=1` core, not a full DEBUG=2 tree, and it is the only
# way to run MemorySanitizer (MSan and ASan cannot share a process, so an
# MSan harness must not dlopen an ASan-built plugin).
#
# The tradeoff: only the harness and the named module are instrumented. A bug
# inside a core helper such as convert.c or parser.c will NOT be reported
# unless you add that file to the command line -- pass it via EXTRA. Prefer
# tools/asan/build.sh + sweep.sh when you are looking for unknown bugs.
#
# Usage:
#   tools/asan/repro.sh <mode> [--hash <line>] [--mutate]
#
#   TOOL=msan  tools/asan/repro.sh 32100 --hash '$krb5asrep$17$'
#   TOOL=ubsan tools/asan/repro.sh 8500  --hash '$racf$*A*00'
#   EXTRA="src/convert.c" tools/asan/repro.sh 8500 --hash '$racf$*A*00'
#
set -u

if [ $# -lt 1 ]; then
  echo "usage: $0 <mode> [--hash <line>] [--mutate]" >&2
  exit 2
fi

MODE=$1; shift

TOOL=${TOOL:-asan}
CC=${CC:-clang}
EXTRA=${EXTRA:-}
OUT=${OUT:-./asan-repro}

# Must be an ordinary DEBUG=1 build. An ASan-instrumented core here makes every
# run abort with "incompatible ASan runtimes" and breaks msan outright.
CORE=${CORE:-./libhashcat.so.7}
CORE_DIR=$(cd "$(dirname "$CORE")" && pwd)

case "$TOOL" in
  asan)  SAN="-fsanitize=address" ;;
  # Deliberately no -fno-sanitize-recover=undefined, matching src/Makefile:
  # aborting on the first UBSan finding hides everything that would have run
  # after it. Use UBSAN_OPTIONS=halt_on_error=1 per run when you want that.
  ubsan) SAN="-fsanitize=undefined" ;;
  both)  SAN="-fsanitize=address,undefined" ;;
  msan)  SAN="-fsanitize=memory -fsanitize-memory-track-origins=2" ;;
  *)     echo "usage: TOOL=asan|ubsan|both|msan $0 ..." >&2; exit 2 ;;
esac

mkdir -p "$OUT"

MOD=$(printf "module_%05d" "$MODE")

# -DSTATIC_MODULE links the module directly rather than dlopen()ing its .so.
#
# MODULE_INTERFACE_VERSION_CURRENT is normally injected per-plugin by
# src/Makefile; a standalone compile has to supply it by hand.
$CC -std=gnu99 -DDEBUG -DSTATIC_MODULE -g -O1 \
    $SAN -fno-omit-frame-pointer \
    -Iinclude/ -IOpenCL/ -Ideps/LZMA-SDK/C -Ideps/zlib -Ideps/zlib/contrib \
    -Ideps/OpenCL-Headers -Ideps/xxHash -Ideps/unrar \
    -DWITH_BRAIN -DWITH_HWMON \
    -DHC_PLUGIN_ABI_VERSION=720 -DMODULE_INTERFACE_VERSION_CURRENT=720 \
    tools/asan/parse_harness.c "src/modules/${MOD}.c" $EXTRA \
    "$CORE" -ldl -o "$OUT/repro_${TOOL}_m${MODE}" -Wl,-rpath,"$CORE_DIR"

# Pin the loader to the core we just linked against; libhashcat.so.7 can
# otherwise resolve to another copy on the search path.
export LD_LIBRARY_PATH="$CORE_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# halt_on_error=0 so a module with two distinct defects reports both.
# use_sigaltstack=0 works around clang runtimes older than glibc 2.34, where
# SIGSTKSZ stopped being a compile-time constant and the runtime computes 0
# ("failed to allocate 0x0 bytes of SetAlternateSignalStack").
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=0:use_sigaltstack=0
export MSAN_OPTIONS=use_sigaltstack=0
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0

# argv[1] is ignored under -DSTATIC_MODULE, but the harness still expects it
exec "$OUT/repro_${TOOL}_m${MODE}" x "$MODE" "$@"
