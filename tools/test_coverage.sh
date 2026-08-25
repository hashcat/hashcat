#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Reports hash-modes that tools/test.sh cannot test, and fails if any of them
# is not on the documented exclusion list below. Run it after adding a mode:
#
#   tools/test_coverage.sh
#
# Nothing here needs a backend device or even a built hashcat; it only reads
# the source tree, so it is cheap enough to run in CI.
#
# A mode counts as covered when it has a test.pl oracle in tools/test_modules/
# or appears in one of test.sh's container mode lists. Those lists are read out
# of test.sh rather than repeated here, so this stays correct when they change.

set -u

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TEST_SH="${TDIR}/test.sh"
MODULE_DIR="${TDIR}/../src/modules"
PM_DIR="${TDIR}/test_modules"

# Modes with no test.sh coverage on purpose. Each line is "<mode> <reason>".
#
# The RC4-40 colliders are two-stage workflows rather than cracks: the #1 mode
# derives an intermediate key that the #2 mode consumes, so the "generate a
# hash for a random password and check it cracks" model does not describe them.
read -r -d '' UNTESTABLE <<'LIST'
2000  STDOUT, a candidate generator with OPTS_TYPE_SELF_TEST_DISABLE, nothing to crack
2501  WPA-EAPOL-PMK, deprecated, test.sh skips it in favour of 22001
16801 WPA-PMKID-PMK, deprecated, test.sh skips it in favour of 22001
9710  MS Office <= 2003 MD5 + RC4 collider #1, not a wordlist or mask crack
9720  MS Office <= 2003 MD5 + RC4 collider #2, not a wordlist or mask crack
9810  MS Office <= 2003 SHA1 + RC4 collider #1, not a wordlist or mask crack
9820  MS Office <= 2003 SHA1 + RC4 collider #2, not a wordlist or mask crack
10410 PDF 1.1 - 1.3 collider #1, not a wordlist or mask crack
10420 PDF 1.1 - 1.3 collider #2, not a wordlist or mask crack
LIST

if [ ! -r "${TEST_SH}" ]; then
  echo "ERROR: cannot read ${TEST_SH}"
  exit 1
fi

# every mode that ships a module
all_modes=$(ls "${MODULE_DIR}"/module_*.c | sed -E 's/.*module_0*([0-9]+)\.c/\1/' | sort -un)

# modes with a test.pl oracle
pm_modes=$(ls "${PM_DIR}"/m*.pm 2>/dev/null | sed -E 's/.*m0*([0-9]+)\.pm/\1/' | sort -un)

# modes covered by a container or reference file, taken from test.sh's own lists
container_modes=$(grep -hoE '^[A-Z0-9_]*MODES="[0-9 ]*"' "${TEST_SH}" \
  | grep -v '^CL_MODES=' \
  | sed -E 's/^[A-Z0-9_]*MODES="//; s/"$//' \
  | tr ' ' '\n' \
  | grep -E '^[0-9]+$' \
  | sort -un)

# CL_MODES is the one list whose entries are not hash modes. 14511 to 14553 are
# the kernel numbers m14500 selects between at runtime, and test.sh uses them as
# names for the cryptoloop container variants it tests; every one of those runs
# ends up invoking hashcat with -m 14500. So the list covers 14500 and nothing
# else, and its own numbers must not be looked for in src/modules.
cl_modes=$(grep -hoE '^CL_MODES="[0-9 ]*"' "${TEST_SH}" \
  | sed -E 's/^CL_MODES="//; s/"$//' \
  | tr ' ' '\n' \
  | grep -E '^[0-9]+$' \
  | sort -un)

if [ -n "${cl_modes}" ]; then
  container_modes=$(printf '%s\n14500\n' "${container_modes}" | sort -un)
fi

covered=$(printf '%s\n%s\n' "${pm_modes}" "${container_modes}" | sort -un)

excluded=$(printf '%s\n' "${UNTESTABLE}" | awk 'NF {print $1}' | sort -un)

uncovered=$(comm -23 <(printf '%s\n' ${all_modes} | sort) <(printf '%s\n' ${covered} | sort))
missing=$(comm -23 <(printf '%s\n' ${uncovered} | sort) <(printf '%s\n' ${excluded} | sort) | sort -n)

# lists can also drift the other way: a mode test.sh believes it tests but that
# no longer ships a module, which reads as coverage and is not
orphans=$(comm -13 <(printf '%s\n' ${all_modes} | sort) <(printf '%s\n' ${container_modes} | sort) | sort -n)

total=$(printf '%s\n' ${all_modes} | grep -c '')
n_uncovered=$(printf '%s\n' ${uncovered} | grep -c '[0-9]')

echo "modules      : ${total}"
echo "with a test  : $((total - n_uncovered))"
echo "excluded     : $(printf '%s\n' ${excluded} | grep -c '[0-9]')"
echo ""

if [ -n "${orphans}" ]; then
  echo "Listed in test.sh but no such module exists:"
  for m in ${orphans}; do
    echo "  ${m}"
  done
  echo ""
fi

if [ -z "${missing}" ]; then
  echo "Every mode has a test or a documented reason not to."

  if [ -n "${orphans}" ]; then
    exit 1
  fi

  exit 0
fi

echo "No test and no documented reason:"

for m in ${missing}; do
  name=$(grep -m1 'HASH_NAME' "${MODULE_DIR}/module_$(printf '%05d' "${m}").c" 2>/dev/null | sed 's/.*= *"//; s/".*//')
  printf '  %-6s %s\n' "${m}" "${name}"
done

echo ""
echo "Add tools/test_modules/m<mode>.pm, or add the mode to UNTESTABLE in this"
echo "script with the reason it cannot have one."

exit 1
