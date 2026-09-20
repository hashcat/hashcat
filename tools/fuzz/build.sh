#!/usr/bin/env bash
#
# Build the fuzz targets in tools/fuzz.
#
# The same script builds them locally and inside OSS-Fuzz. OSS-Fuzz sets CC,
# CFLAGS, LIB_FUZZING_ENGINE, OUT and WORK, and whatever it sets has to be used
# verbatim, because that is how it selects the engine and the sanitizer. Where
# they are unset this builds a local libFuzzer plus AddressSanitizer binary.
#
# Usage:
#   tools/fuzz/build.sh            # from the hashcat source root
#
# Needs clang. libFuzzer is a clang feature and gcc has no equivalent, which is
# the one thing this build does not share with the DEBUG=2 build in src/Makefile.

set -eu

CC=${CC:-clang}
CXX=${CXX:-clang++}
OUT=${OUT:-./fuzz_out}
WORK=${WORK:-${OUT}/work}
LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}
CFLAGS=${CFLAGS:--g -O1 -fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer}
CXXFLAGS=${CXXFLAGS:-$CFLAGS}

if [ ! -f src/rp.c ]; then
  echo "error: run this from the hashcat source root" >&2
  exit 2
fi

mkdir -p "$OUT" "$WORK"

# What a target has to be linked against. This is not the whole core: it is
# what the two entry points reach, resolved by following the undefined symbols
# until the link succeeds. Nothing here needs a library outside the tree,
# because zlib, LZMA and zstd are reached through ext_zlib.c, ext_lzma.c and
# ext_zstd.c, which load them at run time.

CORE="src/rp.c
      src/rp_cpu.c
      src/parser.c
      src/memory.c
      src/convert.c
      src/shared.c
      src/filehandling.c
      src/ext_zlib.c
      src/ext_lzma.c
      src/ext_zstd.c
      src/paw64.c
      src/folder.c
      src/timer.c
      src/dynloader.c
      src/path.c
      src/system.c
      src/memchr.c
      src/cpu_features.c
      tools/fuzz/stubs.c"

INCLUDES="-Iinclude/ -IOpenCL/ -Ideps/OpenCL-Headers"
DEFINES="-DWITH_BRAIN -DWITH_HWMON"

objs=""

for src in $CORE; do
  obj="${WORK}/$(basename "$src" .c).o"

  # shellcheck disable=SC2086
  $CC $CFLAGS -std=gnu99 $INCLUDES $DEFINES -c "$src" -o "$obj"

  objs="$objs $obj"
done

for target in rule tokenizer; do
  obj="${WORK}/fuzz_${target}.o"

  # shellcheck disable=SC2086
  $CC $CFLAGS -std=gnu99 $INCLUDES $DEFINES -c "tools/fuzz/fuzz_${target}.c" -o "$obj"

  # OSS-Fuzz links every target with the C++ driver, C project or not
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS "$obj" $objs $LIB_FUZZING_ENGINE -o "${OUT}/fuzz_${target}"

  cp "tools/fuzz/fuzz_${target}.dict"    "${OUT}/"
  cp "tools/fuzz/fuzz_${target}.options" "${OUT}/"

  echo "built ${OUT}/fuzz_${target}"
done

# Seed corpora. OSS-Fuzz picks up <target>_seed_corpus.zip beside the binary;
# a local run takes the directories the same script writes.

tools/fuzz/seeds.sh "${WORK}/seeds"

if command -v zip >/dev/null 2>&1; then
  for target in rule tokenizer; do
    (cd "${WORK}/seeds/${target}" && zip -q -r "${OUT}/fuzz_${target}_seed_corpus.zip" .)

    echo "built ${OUT}/fuzz_${target}_seed_corpus.zip"
  done
fi
