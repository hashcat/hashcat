#!/usr/bin/env bash
#
# Build the fully-instrumented host-parser harness.
#
# Everything is instrumented: the harness, libhashcat.so.7 and the 594 module
# plugins. That matters -- several real bugs live in core helpers
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

if [ ! -f src/modules/module_00000.c ]; then
  echo "error: run this from the hashcat source root" >&2
  exit 2
fi

if [ "${1:-}" = "--with-make" ]; then
  make DEBUG=2 -j"$(nproc)"
fi

if [ ! -f ./libhashcat.so.7 ]; then
  echo "error: ./libhashcat.so.7 not found -- run 'make DEBUG=2 -j\$(nproc)' first" >&2
  exit 2
fi

if ! nm -D ./libhashcat.so.7 | grep -q asan; then
  echo "warning: ./libhashcat.so.7 is not ASan-instrumented." >&2
  echo "         Bugs inside core helpers will not be reported. Rebuild with DEBUG=2." >&2
fi

# gcc, not clang. hashcat's DEBUG=2 build links the shared libasan.so, while
# clang statically links its own ASan runtime; mixing the two makes every run
# abort with "Your application is linked against incompatible ASan runtimes".
$CC -std=gnu99 -DDEBUG -Og -ggdb -fsanitize=address -fno-omit-frame-pointer \
    -Iinclude/ -IOpenCL/ -Ideps/LZMA-SDK/C -Ideps/zlib -Ideps/zlib/contrib \
    -Ideps/OpenCL-Headers -Ideps/xxHash -Ideps/unrar \
    -DWITH_BRAIN -DWITH_HWMON -DHC_PLUGIN_ABI_VERSION=720 \
    tools/asan/parse_harness.c ./libhashcat.so.7 -ldl \
    -o "$OUT" -Wl,-rpath,'$ORIGIN'

echo "built $OUT"
