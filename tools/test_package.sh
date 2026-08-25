#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Run an unpacked hashcat directory and check that it works.
#
# A build that links is not a build that runs. What is checked here is that the binary starts, that
# it finds its core, that every module loads, that a feed produces candidates, and that a kernel
# compiles and cracks a hash.
#
# The first group needs no backend device, so it runs anywhere, including inside a build VM. The
# second group needs one OpenCL device and a CPU device is enough. --no-device leaves that group out
# and prints that it did, so a run without a device cannot be mistaken for a full one.
#
# The directory is the tree a build wrote or an archive was unpacked into, so the binary is asked to
# find everything the way a user's copy does.
#
# usage: tools/test_package.sh [directory] [--no-device]

set -u

DIR="."
WANT_DEVICE=1

for ARG in "$@"; do
  case "$ARG" in
    --no-device) WANT_DEVICE=0 ;;
    --help)      echo "usage: $0 [directory] [--no-device]"; exit 0 ;;
    *)           DIR="$ARG" ;;
  esac
done

cd "$DIR" || exit 1

# what the binary and the plugins are called here

case "$(uname -s)" in
  CYGWIN*|MINGW*|MSYS*) PLUGIN_SUFFIX="dll"; CANDIDATES="./hashcat.exe";            LIBRARIES="hashcat.dll" ;;
  *)                    PLUGIN_SUFFIX="so";  CANDIDATES="./hashcat.bin ./hashcat";  LIBRARIES="libhashcat.so.* libhashcat.*.dylib" ;;
esac

HC=""

for CANDIDATE in $CANDIDATES; do
  if [ -x "$CANDIDATE" ]; then
    HC="$CANDIDATE"
    break
  fi
done

if [ -z "$HC" ]; then
  echo "! No hashcat binary in $(pwd), looked for $CANDIDATES"
  exit 1
fi

LIBRARY=""

for CANDIDATE in $LIBRARIES; do
  if [ -f "$CANDIDATE" ]; then
    LIBRARY="$CANDIDATE"
    break
  fi
done

# the scratch files are named relative to the package, because the binary is native on Windows while
# the shell running it is not, and an absolute path from one is not a path to the other

WORK="$(mktemp -d ./package_test.XXXXXX)"

TMP_ON_DISK="$(mktemp)"
TMP_LOADED="$(mktemp)"

# one trap, because a second one replaces the first rather than adding to it, and the scratch
# directory this makes inside the package under test is then left behind on every run

trap 'rm -rf "$WORK" "$TMP_ON_DISK" "$TMP_LOADED"' EXIT

FAILURES=0

pass ()
{
  printf 'ok    %s\n' "$1"
}

fail ()
{
  printf 'FAIL  %s\n' "$1"
  FAILURES=$((FAILURES + 1))
}

# a line count that is a bare number on every platform, wc pads it on some

count ()
{
  wc -l | tr -d '[:space:]'
}

echo "## $(pwd), $(du -sh . 2>/dev/null | cut -f1) unpacked"
echo ""
echo "## checks that need no backend device"
echo ""

# the binary starts at all, which on a shared arrangement means the loader found the core beside it

VERSION="$("$HC" --version 2>&1)"

case "$VERSION" in
  v[0-9]*) pass "the binary starts, $HC is $VERSION" ;;
  *)       fail "the binary did not report a version, it said: $VERSION" ;;
esac

# and the core it found is this directory's. Moving the library aside has to break the binary,
# otherwise it is resolving a core installed somewhere else and the package proves nothing

if [ -n "$LIBRARY" ]; then
  mv "$LIBRARY" "$LIBRARY.hidden"

  "$HC" --version >/dev/null 2>&1

  RC=$?

  mv "$LIBRARY.hidden" "$LIBRARY"

  if [ "$RC" -eq 0 ]; then
    fail "the binary still ran with $LIBRARY moved aside, so its core comes from somewhere else"
  else
    pass "the core is $LIBRARY from this directory"
  fi
else
  pass "no core library here, the arrangement is static"
fi

# every module is loaded and asked for its name, so a module whose imports do not resolve is named
# rather than found by the first user of that hash mode

MODULES="$(ls modules/module_*."$PLUGIN_SUFFIX" 2>/dev/null | count)"
LISTED="$("$HC" --hash-info --quiet 2>/dev/null | grep -c '^Hash mode #')"

if [ "$MODULES" -eq 0 ]; then
  fail "no modules in modules/, the package is incomplete"
elif [ "$LISTED" -eq "$MODULES" ]; then
  pass "all $MODULES modules load"
else
  # a count says something is wrong and nothing about what, so the modes present on disk and the
  # modes hashcat answered with are compared and the difference is named

  ls modules/module_*."$PLUGIN_SUFFIX" 2>/dev/null | sed 's/.*module_0*\([0-9]*\)\..*/\1/' | sort -n > "$TMP_ON_DISK"
  "$HC" --hash-info --quiet 2>/dev/null | sed -n 's/^Hash mode #0*\([0-9]*\).*/\1/p'   | sort -n > "$TMP_LOADED"

  MISSING="$(comm -23 "$TMP_ON_DISK" "$TMP_LOADED" | tr '\n' ' ' | sed 's/ $//')"

  fail "$LISTED of $MODULES modules load, missing: $MISSING"

  # the count and the mode number still do not say why, and the loader does

  FIRST="${MISSING%% *}"

  "$HC" -m "$FIRST" --hash-info 2>&1 | grep -iE 'built for plugin interface|cannot load|undefined|no such file' | head -2 | sed 's/^/      /'
fi

# a plugin hands the core its entry point and keeps everything else to itself. A plugin that exports
# more than that is offering names to whatever else is loaded into the same process, and an offer
# nobody meant to make is one somebody eventually depends on. One module, one name.

# _ZTI8RAR_EXIT and _ZTS8RAR_EXIT are a C++ type description. UnRAR throws a value and catches it
# again, and the compiler gives the type description of a thrown type default visibility whatever it
# is asked for, so where UnRAR is linked in those two names get out and no source change stops them.
# GCC does honour hidden visibility on the type description of a class, so the fix is upstream's to
# make. The two are named rather than matched by shape, so a plugin that leaks a type description of
# its own is still reported.

# __bss_start, _edata and _end are the linker's own. They mark where the sections end and no source
# file declares them, so they are not API in any arrangement and nothing a plugin does puts them
# there or takes them away. GNU ld only defines them where something refers to them, which in a
# plugin is nothing, so a native build never shows them; lld defines them in every shared object it
# writes, so the cross build shows them on all 593. That is a difference between two linkers about
# their own bookkeeping and not one about what a plugin offers, so it is read out here.

plugin_exports ()
{
  case "$(uname -s)" in
    # objdump prints two tables that both begin with a bracketed index. The addresses come first and
    # the names after, so the names are read only inside the table that holds them, otherwise a line
    # of the address table is reported as an exported name. Newer binutils also prints an ordinal and
    # a hint ahead of the name inside that table, so everything up to the last space goes.
    CYGWIN*|MINGW*|MSYS*) objdump -p "$1" | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$/ s/^\t\[ *[0-9][0-9]*\].* //p' ;;
    Darwin)               nm -g -U "$1" | awk '{ print $NF }' | sed 's/^_//' ;;
    *)                    nm -DgP "$1" | awk '$2 != "U" && $2 != "w" { print $1 }' ;;
  # What comes back is filtered twice. The first list is the two C++ typeinfo symbols UnRAR's exception
  # type leaves behind, which are hashcat's own and known to be harmless. The second rule drops the
  # names the implementation reserves for itself, which is everything beginning with an underscore, and
  # is where a toolchain puts its housekeeping. Linux publishes none of those in .dynsym, FreeBSD
  # publishes _init and _fini, and the next toolchain will publish a different set again, so the rule
  # names the class instead of listing the members. __bss_start, _edata and _end were the members it
  # used to list. A mangled C++ name begins with _Z and is deliberately kept, because one of those in a
  # plugin is a real export rather than housekeeping.
  esac | grep -v -x -e '_ZTI8RAR_EXIT' -e '_ZTS8RAR_EXIT' | grep -v -E '^_([^Z]|$)'
}

check_exports ()
{
  DIRECTORY="$1"
  PREFIX="$2"
  EXPECTED="$3"
  EXPECTED_ALT="${4:-}"

  SEEN=0
  WRONG=0

  for PLUGIN in "$DIRECTORY"/"$PREFIX"*."$PLUGIN_SUFFIX"; do
    [ -f "$PLUGIN" ] || continue

    SEEN=$((SEEN + 1))

    NAMES="$(plugin_exports "$PLUGIN" | sort | tr '\n' ' ' | sed 's/ $//')"

    if [ "$NAMES" = "$EXPECTED" ]; then
      continue
    fi

    if [ "$NAMES" = "$EXPECTED_ALT" ]; then
      continue
    fi

    WRONG=$((WRONG + 1))

    if [ "$WRONG" -le 3 ]; then
      printf '      %s exports: %s\n' "$PLUGIN" "$NAMES"
    fi
  done

  if [ "$SEEN" -eq 0 ]; then
    fail "nothing in $DIRECTORY/ to check"
  elif [ "$WRONG" -eq 0 ]; then
    pass "all $SEEN plugins in $DIRECTORY/ export exactly what the core resolves"
  else
    fail "$WRONG of $SEEN plugins in $DIRECTORY/ do not export exactly: $EXPECTED"
  fi
}

# one exported name is what the shared arrangement promises. A static plugin carries the core inside
# itself, and which of those names stay in its dynamic symbol table is up to the platform's linker,
# so there is nothing to hold it to here.
#
# A feed has two shapes it may take. One generates candidates on the host alone. One also generates
# them on the device, and it exports global_dev_init () and thread_next_dev () on top for that, so
# both name lists are given here.

if [ -n "$LIBRARY" ]; then
  check_exports modules module_ "module_init"
  check_exports bridges bridge_ "bridge_init"
  check_exports feeds   ""       "GENERIC_PLUGIN_OPTIONS GENERIC_PLUGIN_VERSION global_init global_keyspace global_term thread_init thread_next thread_seek thread_term" \
                                 "GENERIC_PLUGIN_OPTIONS GENERIC_PLUGIN_VERSION global_dev_init global_init global_keyspace global_term thread_init thread_next thread_next_dev thread_seek thread_term"
fi

# and the other direction. Where there is a core library, a plugin calls the core through it and
# names it in its own dependencies. A plugin that names nothing carries a copy of the core instead,
# and dropped into a package built the other way it loads, runs, and holds a second core in the same
# process with nothing to say so. Nothing at load time can tell the two apart, because such a plugin
# is complete and still exports only its entry point. So it is caught here, before the package ships.
#
# The Rust feed is the exception on purpose. It is written in Rust, it calls nothing in the core, and
# cargo never sees a link line, so it depends on the core in neither arrangement.

plugin_needs ()
{
  case "$(uname -s)" in
    CYGWIN*|MINGW*|MSYS*) objdump -p "$1" | sed -n 's/^\tDLL Name: //p' ;;
    Darwin)               otool -L "$1" | sed -n 's:^\t\([^ ]*\).*:\1:p' ;;
    *)                    objdump -p "$1" | awk '$1 == "NEEDED" { print $2 }' ;;
  esac | sed 's:.*/::'
}

check_core_link ()
{
  DIRECTORY="$1"

  SEEN=0
  WRONG=0

  for PLUGIN in "$DIRECTORY"/*."$PLUGIN_SUFFIX"; do
    [ -f "$PLUGIN" ] || continue

    # a Rust plugin is a cdylib that calls nothing in the core, so there is no core for it to name.
    # The test is the file name because that is what tells the two apart from the outside, which does
    # mean a C plugin with rust in its name would be skipped as well. There is none.
    case "$PLUGIN" in *rust_*) continue ;; esac

    SEEN=$((SEEN + 1))

    if plugin_needs "$PLUGIN" | grep -q "^$(basename "$LIBRARY")$"; then
      continue
    fi

    WRONG=$((WRONG + 1))

    if [ "$WRONG" -le 3 ]; then
      printf '      %s does not link %s\n' "$PLUGIN" "$LIBRARY"
    fi
  done

  if [ "$SEEN" -eq 0 ]; then
    fail "nothing in $DIRECTORY/ to check"
  elif [ "$WRONG" -eq 0 ]; then
    pass "all $SEEN plugins in $DIRECTORY/ take their core from $LIBRARY"
  else
    fail "$WRONG of $SEEN plugins in $DIRECTORY/ carry their own core instead of linking $LIBRARY"
  fi
}

if [ -n "$LIBRARY" ]; then
  check_core_link modules
  check_core_link bridges
  check_core_link feeds
fi

# a package without example.dict starts, lists every module, and still cannot run the attack every
# first time user runs. Whether the words come out the other end is asked further down, because
# reading them means starting the candidate pipeline and that wants a backend platform.

if [ -f example.dict ]; then
  pass "example.dict is in the package, $(count < example.dict) words"
else
  fail "no example.dict here, the package is incomplete"
fi

if [ "$WANT_DEVICE" -eq 0 ]; then
  echo ""
  echo "## not run: the checks that need a backend device, --no-device was given"
else
  echo ""
  echo "## checks that need one backend device"
  echo ""

  # --stdout runs the candidate pipeline, which starts the backend like an attack does. With no
  # platform present hashcat prints why and exits, so these say nothing without a device.

  CANDIDATES_SEEN="$("$HC" --stdout -a 3 '?d?d?d?d' 2>/dev/null | count)"

  if [ "$CANDIDATES_SEEN" -eq 10000 ]; then
    pass "a mask attack produces its 10000 candidates"
  else
    fail "a mask attack produced $CANDIDATES_SEEN candidates instead of 10000"
  fi

  if [ -f example.dict ]; then
    WORDS="$(count < example.dict)"
    CANDIDATES_SEEN="$("$HC" --stdout -a 0 example.dict 2>/dev/null | count)"

    if [ "$CANDIDATES_SEEN" -eq "$WORDS" ]; then
      pass "the wordlist feed produces all $WORDS candidates of example.dict"
    else
      fail "the wordlist feed produced $CANDIDATES_SEEN candidates of the $WORDS in example.dict"
    fi
  fi

  DEVICES="$("$HC" -I 2>&1 | grep -c 'Backend Device ID')"

  if [ "$DEVICES" -ge 1 ]; then
    pass "$DEVICES backend device(s) available"
  else
    fail "no backend device, the checks below cannot say anything"
  fi

  printf 'hashcat\nhashcat1\nhashcat2\n' > "$WORK/one.dict"

  # a fast hash off a mask. The self test of the mode runs first, so this is the module, the kernel
  # build and the crack in one

  OUT="$("$HC" -m 0 -a 3 --quiet --potfile-disable e48e13207341b6bffb7fb1622282247b '?d?d?d?d' 2>&1)"

  case "$OUT" in
    *:1337*) pass "mode 0 self tests and cracks off a mask" ;;
    *)       fail "mode 0 did not crack off a mask, it said: $OUT" ;;
  esac

  # a slow hash off a wordlist, which is the other kernel shape and the other candidate source

  OUT="$("$HC" -m 500 -a 0 --quiet --potfile-disable '$1$28772684$iEwNOgGugqO9.bIz5sk8k/' "$WORK/one.dict" 2>&1)"

  case "$OUT" in
    *:hashcat*) pass "mode 500 self tests and cracks off a wordlist" ;;
    *)          fail "mode 500 did not crack off a wordlist, it said: $OUT" ;;
  esac

  # two hashes that fail to parse for two different reasons have to be reported for those two
  # reasons. The failure this catches is the second line inheriting the first line's message.
  # The outfile check is on because it puts a second thread on the same reporting path

  printf '$1$abcdefgh\n$1$abcdefgh$!!!!!!!!!!!!!!!!!!!!!!\n' > "$WORK/broken.hash"

  OUT="$("$HC" -m 500 -a 0 --quiet --potfile-disable --outfile-check-dir "$WORK" "$WORK/broken.hash" "$WORK/one.dict" 2>&1)"

  SEPARATOR="$(echo "$OUT" | grep -c 'Separator unmatched')"
  ENCODING="$(echo "$OUT" | grep -c 'Token encoding exception')"

  if [ "$SEPARATOR" -ge 1 ] && [ "$ENCODING" -ge 1 ]; then
    pass "two unparsable hashes are reported for their own two reasons"
  else
    fail "two unparsable hashes were not reported apart, it said: $OUT"
  fi
fi

echo ""

if [ "$FAILURES" -eq 0 ]; then
  echo "## $HC: every check passed"
  exit 0
fi

echo "## $HC: $FAILURES check(s) failed"
exit 1
