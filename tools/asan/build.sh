#!/usr/bin/env bash
#
# Build the fully-instrumented host-parser harness.
#
# Everything is instrumented: the harness, libhashcat.so.7 and the 594 module
# plugins. That matters: several real bugs live in core helpers
# (convert.c, parser.c) rather than in the module that calls them, and a
# harness linked against an uninstrumented core reports those runs as clean.
#
# Usage:
#   tools/asan/build.sh          # from the hashcat source root
#
# Prerequisite: a `make DEBUG=2` tree. Run this script with --with-make to do
# that here, or do it yourself first.

set -eu

CC=${CC:-gcc}
OUT=${OUT:-./asan_harness}

# Which sanitizers to build with. Must match what the tree itself was built
# with, or the runtimes disagree at load time.
#   SANITIZE=address              (default)
#   SANITIZE=address,undefined    ASan + UBSan
#   SANITIZE=undefined            UBSan alone, much faster
SANITIZE=${SANITIZE:-address}

if [ ! -f src/modules/module_00000.c ]; then
  echo "error: run this from the hashcat source root" >&2
  exit 2
fi

if [ "${1:-}" = "--with-make" ]; then
  make clean
  make DEBUG=2 SANITIZE="$SANITIZE" -j"$(nproc)"
fi

if [ ! -f ./libhashcat.so.7 ]; then
  echo "error: ./libhashcat.so.7 not found, run 'make DEBUG=2 -j\$(nproc)' first" >&2
  exit 2
fi

if ! nm -D ./libhashcat.so.7 | grep -q asan; then
  echo "warning: ./libhashcat.so.7 is not ASan-instrumented." >&2
  echo "         Bugs inside core helpers will not be reported. Rebuild with DEBUG=2." >&2
fi

case "$SANITIZE" in
  *undefined*)
    if ! nm -D ./libhashcat.so.7 | grep -q ubsan; then
      echo "warning: SANITIZE=$SANITIZE but ./libhashcat.so.7 has no UBSan symbols." >&2
      echo "         make does not track flag changes, so switching SANITIZE needs a" >&2
      echo "         clean rebuild:  make clean && make DEBUG=2 SANITIZE=$SANITIZE" >&2
    fi ;;
esac

# gcc by default, to match how the DEBUG=2 tree itself was built. CC=clang
# works too on a stock toolchain (both link the same shared libasan.so.6).
# What actually matters is that the libhashcat resolved at run time is the same
# ASan-instrumented one linked here, hence the rpath below. Mismatch there is
# what produces "Your application is linked against incompatible ASan runtimes".
$CC -std=gnu99 -DDEBUG -Og -ggdb -fsanitize=$SANITIZE -fno-omit-frame-pointer \
    -Iinclude/ -IOpenCL/ -Ideps/LZMA-SDK/C -Ideps/zlib -Ideps/zlib/contrib \
    -Ideps/OpenCL-Headers -Ideps/xxHash -Ideps/unrar \
    -DWITH_BRAIN -DWITH_HWMON -DHC_PLUGIN_ABI_VERSION=720 \
    tools/asan/parse_harness.c ./libhashcat.so.7 -ldl \
    -o "$OUT" -Wl,-rpath,'$ORIGIN'

echo "built $OUT (-fsanitize=$SANITIZE)"
