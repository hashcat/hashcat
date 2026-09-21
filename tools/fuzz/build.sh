#!/usr/bin/env bash
#
# Build the fuzz targets in tools/fuzz.
#
# One script for a local build and for a build service. A service sets CC,
# CFLAGS, LIB_FUZZING_ENGINE, OUT and WORK, and whatever it sets has to be used
# verbatim, because that is how it selects the engine and the sanitizer. Where
# they are unset this builds a local libFuzzer plus AddressSanitizer binary.
# OSS-Fuzz is the service this shape comes from, should the project ever want
# these run there.
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

# Absolute from here on. OUT defaults to a relative path, the seed corpora are zipped from inside
# the directory they live in, and a relative OUT does not survive that cd: zip reports
# "Could not create output file" and the build fails on a machine that took the default.

OUT=$(cd "$OUT" && pwd)
WORK=$(cd "$WORK" && pwd)

# What a target is linked against: the code the entry points actually reach,
# and nothing else. The file layer, the folder layout and the random generator
# are stubbed in tools/fuzz/stubs.c rather than linked, which keeps the
# compression libraries and the rest of the tool out of a target that never
# opens a file.

CORE="src/rp.c
      src/rp_cpu.c
      src/parser.c
      src/memory.c
      src/convert.c
      src/shared.c
      src/paw64.c
      src/timer.c
      src/bitops.c
      src/cpu_crc32.c
      src/keyboard_layout.c
      src/ext_lzma.c
      src/ext_zlib.c
      src/dynloader.c
      src/folder.c
      src/path.c
      src/plugin_abi.c
      tools/asan/hashconfig.c
      tools/fuzz/stubs.c"

# Some modules reach into the OpenCL emulation, because a parser that has to
# undo what a kernel did calls the same code the kernel does. Which ones is not
# worth tracking by hand, so every emu file is compiled and the linker takes
# what it needs.

CORE="$CORE $(ls src/emu_*.c)"

# tools/asan is on the include path for hashconfig.h, the one copy of the
# hashconfig a parser sees, shared with the harness in tools/asan/

INCLUDES="-Iinclude/ -IOpenCL/ -Ideps/OpenCL-Headers -Itools/asan"

# Vendored headers, where the tree still carries them. types.h includes the
# LZMA and zlib headers directly on a tree from before those libraries were
# loaded at run time, and nothing compiles without them there.

for dep in deps/LZMA-SDK/C deps/zlib deps/zlib/contrib deps/xxHash deps/unrar; do
  [ -d "$dep" ] && INCLUDES="$INCLUDES -I$dep"
done

# The plugin interface version comes out of src/Makefile rather than being
# written here twice, because a module refuses to compile without it and a
# stale copy would be a confusing way to find that out.

ABI=$(sed -n 's/^MODULE_INTERFACE_VERSION *:*= *\([0-9]*\).*/\1/p' src/Makefile | head -1)

if [ -z "$ABI" ]; then
  echo "error: no MODULE_INTERFACE_VERSION in src/Makefile" >&2
  exit 2
fi

DEFINES="-DWITH_BRAIN -DWITH_HWMON -DHC_PLUGIN_ABI_VERSION=${ABI} -DMODULE_INTERFACE_VERSION_CURRENT=${ABI}"

# A tree that predates a file simply does not have it: keep what is there and
# let the link say if something the targets actually need is missing.

present=""

for src in $CORE; do
  [ -f "$src" ] && present="$present $src"
done

CORE="$present"

objs=""
targets=""

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

  # the C++ driver links every target, C project or not
  # shellcheck disable=SC2086
  $CXX $CXXFLAGS "$obj" $objs $LIB_FUZZING_ENGINE -o "${OUT}/fuzz_${target}"

  cp "tools/fuzz/fuzz_${target}.dict"    "${OUT}/"
  cp "tools/fuzz/fuzz_${target}.options" "${OUT}/"

  echo "built ${OUT}/fuzz_${target}"

  targets="$targets ${target}"
done

# One parser target per mode, because every src/modules/module_XXXXX.c defines
# module_init, module_hash_decode and the rest of the API with external
# linkage: two modules in one link is a duplicate symbol. Each target links its
# own module statically, so there is no plugin to ship beside the binary, and
# each keeps its own corpus, which is what a per mode format deserves anyway.
#
# The list is a starting set rather than all 600: the modes whose parsers have
# needed a memory safety fix before, one that carries a rounds field, and one
# whose format is a long chain of star separated fields.

FUZZ_MODES=${FUZZ_MODES:-"07400 17225 22000 29100"}

for mode in $FUZZ_MODES; do
  module="src/modules/module_${mode}.c"

  if [ ! -f "$module" ]; then
    echo "warning: no ${module}, skipping" >&2
    continue
  fi

  # -DFUZZ_HASH_MODE takes the mode as hashcat writes it on the command line. 10# rather than
  # stripping the zeros with sed, which turns 00000 into nothing at all and hands the compiler an
  # empty -DFUZZ_HASH_MODE=

  hash_mode=$((10#$mode))

  # shellcheck disable=SC2086
  $CC $CFLAGS -std=gnu99 $INCLUDES $DEFINES -DFUZZ_HASH_MODE=${hash_mode} \
      -c tools/fuzz/fuzz_parse.c -o "${WORK}/fuzz_parse_${hash_mode}.o"

  # shellcheck disable=SC2086
  $CC $CFLAGS -std=gnu99 $INCLUDES $DEFINES -c "$module" -o "${WORK}/module_${mode}.o"

  # shellcheck disable=SC2086
  $CXX $CXXFLAGS "${WORK}/fuzz_parse_${hash_mode}.o" "${WORK}/module_${mode}.o" $objs \
      $LIB_FUZZING_ENGINE -o "${OUT}/fuzz_parse_${hash_mode}"

  cp "tools/fuzz/fuzz_parse.dict" "${OUT}/"

  printf '[libfuzzer]\ndict = fuzz_parse.dict\nmax_len = 8192\n' > "${OUT}/fuzz_parse_${hash_mode}.options"

  echo "built ${OUT}/fuzz_parse_${hash_mode}"

  targets="$targets parse_${hash_mode}"
done

# Seed corpora. A build service picks up <target>_seed_corpus.zip beside the
# binary; a local run takes the directories the same script writes.

tools/fuzz/seeds.sh "${WORK}/seeds" $FUZZ_MODES

if command -v zip >/dev/null 2>&1; then
  for target in $targets; do
    [ -d "${WORK}/seeds/${target}" ] || continue

    (cd "${WORK}/seeds/${target}" && zip -q -r "${OUT}/fuzz_${target}_seed_corpus.zip" .)

    echo "built ${OUT}/fuzz_${target}_seed_corpus.zip"
  done
fi
