#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Tests --lookup for every attack mode that answers it: -a 0, -a 1, -a 3, -a 6 and -a 7.
#
#   tools/test_lookup.sh            # the checks that need no device
#   tools/test_lookup.sh --crack    # and the ones that crack a hash
#   tools/test_lookup.sh --help
#
# --lookup opens no device and reads no hashes, so everything except --crack runs on a machine with
# no backend at all and is cheap enough for CI.
#
# The oracle is --stdout, and the two sides share no code: --lookup inverts the attack's arithmetic
# to rank one candidate, --stdout walks the dispatcher and the kernels forwards to emit all of them.
#
# What makes them comparable is that every report names the window its answer sits in:
#
#   lookup: -s 209 -l 1 runs the one cell of 676 candidates that holds it, where it is number 80
#
# So a check replays exactly that window. Run --stdout on the same attack with "-s 209 -l 1" and it
# has to emit 676 candidates with the one asked about at position 80. That costs one cell rather than
# a walk of the keyspace, it needs no arithmetic of the test's own, and it reads the same for every
# mode. The window before it is replayed too and must NOT hold the candidate, which is what makes the
# reported offset the first the run reaches rather than merely one that works.
#
# Two things --stdout cannot mirror, both handled where they come up:
#
#   - it forces -m 2000, and the hash mode feeds pw_max and the uppercase, UTF-16 and appended-salt
#     options, which feed the -a 3 base word split and so the size of a cell. Every replayed check
#     passes -m 2000 to --lookup as well, so both sides size the cell the same way.
#   - it refuses -S, so the one branch of the -a 3 report that counts -s in candidates cannot be
#     replayed. Its wording is checked instead.
#
# --crack adds the end to end check the oracle cannot make: that the offset --lookup reports is one a
# real attack cracks the hash at, and that the offset before it is not. It needs a working backend,
# so pass anything that run needs through HC_OPTS:
#
#   HC_OPTS="-D 1 --force" tools/test_lookup.sh --crack

set -u

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT="$( cd "${TDIR}/.." && pwd )"

HC="${ROOT}/hashcat"
DICT="${ROOT}/example.dict"

CRACK=0
HC_OPTS="${HC_OPTS:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    -c|--crack) CRACK=1 ;;
    -h|--help)
      sed -n '8,42p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown option: $1, try --help"
      exit 1
      ;;
  esac
  shift
done

for f in "${HC}" "${DICT}"; do
  if [ ! -r "${f}" ]; then
    echo "ERROR: cannot read ${f}"
    [ "${f}" = "${HC}" ] && echo "Run make first, this tests the hashcat in the repo root."
    exit 1
  fi
done

WORK="$( mktemp -d )"

cleanup ()
{
  rm -rf "${WORK}"
}

trap cleanup EXIT INT

# A seekdb path of its own, a potfile and a logfile it does not write: a test leaves nothing in the
# tree it ran from.
COMMON=( --potfile-disable --logfile-disable --seekdb-path="${WORK}/seekdb" )

mkdir -p "${WORK}/seekdb"

PASS=0
FAIL=0

##
## every check reports through these
##

LAST_CMD=""
LAST_OUT=""

fail_out ()
{
  local label="$1" want="$2"

  FAIL=$((FAIL + 1))

  echo "FAIL: ${label}"
  echo "  ran     : ${LAST_CMD}"
  echo "  expected: ${want}"
  echo "  got     :"
  printf '%s\n' "${LAST_OUT}" | sed 's/^/    /'
  echo ""
}

lookup ()
{
  LAST_CMD="hashcat --lookup=$1 ${*:2}"
  LAST_OUT="$( "${HC}" --lookup="$1" "${COMMON[@]}" "${@:2}" 2>&1 )"
}

check_has ()
{
  local label="$1" needle="$2"

  if printf '%s\n' "${LAST_OUT}" | grep -qF -e "${needle}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  fail_out "${label}" "a line holding '${needle}'"

  return 1
}

check_not ()
{
  local label="$1" needle="$2"

  if ! printf '%s\n' "${LAST_OUT}" | grep -qF -e "${needle}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  fail_out "${label}" "no line holding '${needle}'"

  return 1
}

check_re ()
{
  local label="$1" pattern="$2"

  if printf '%s\n' "${LAST_OUT}" | grep -qE -e "${pattern}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  fail_out "${label}" "a line matching /${pattern}/"

  return 1
}

check_eq ()
{
  local label="$1" want="$2" got="$3"

  if [ "${want}" = "${got}" ]; then
    PASS=$((PASS + 1))
    return 0
  fi

  FAIL=$((FAIL + 1))

  echo "FAIL: ${label}"
  echo "  ran     : ${LAST_CMD}"
  echo "  expected: ${want}"
  echo "  got     : ${got}"
  echo ""

  return 1
}

note ()
{
  echo "## $*"
}

##
## the oracle
##

# Replay the window a report names, and check the report against what comes out of it.
#
# Takes the candidate and then the attack, exactly as it would be typed after --lookup. Both sides
# are given -m 2000, because --stdout forces that hash mode and the hash mode decides how a -a 3 base
# word is split, which decides the size of the cell the two are comparing.

replay ()
{
  local cand="$1"; shift

  local label="-a ${2} '${cand}'"

  lookup "${cand}" -m 2000 "$@"

  # What the report says: the offset, the size of the cell it sits in, and where in that cell it is.
  # Not every mode prints a cell. -a 0 has none, because one base word is one candidate there.

  local off cell pos

  off="$(  printf '%s\n' "${LAST_OUT}" | sed -n 's/^lookup: this run reaches it at -s \([0-9]*\),.*/\1/p' )"
  cell="$( printf '%s\n' "${LAST_OUT}" | sed -n 's/^lookup: -s [0-9]* -l 1 runs the one cell of \([0-9]*\) candidates.*/\1/p' )"
  pos="$(  printf '%s\n' "${LAST_OUT}" | sed -n 's/^lookup: -s [0-9]* -l 1 runs the one cell of [0-9]* candidates that holds it, where it is number \([0-9]*\)$/\1/p' )"

  if [ -z "${off}" ]; then
    fail_out "${label}: an offset is reported" "a \"reaches it at -s N\" line"

    return 1
  fi

  # The window itself, from the run's own candidate generator.

  local win="${WORK}/window.txt"

  "${HC}" --stdout "${COMMON[@]}" "$@" -s "${off}" -l 1 > "${win}" 2>/dev/null

  LAST_CMD="hashcat --stdout ${*} -s ${off} -l 1"
  LAST_OUT="$( printf 'the window holds %s candidates:\n' "$( wc -l < "${win}" )"; head -c 2000 "${win}" )"

  # Where the candidate actually is in it. grep counts from 1 and so does the report.

  local at
  at="$( grep -n -x -F -m1 -e "${cand}" "${win}" | cut -d: -f1 )"

  check_eq "${label}: the window holds it where the report says" "${pos:-1}" "${at:-absent}"

  if [ -n "${cell}" ]; then
    check_eq "${label}: the window is the size the report gives" "${cell}" "$( wc -l < "${win}" )"
  fi

  # The window before it must not hold it, or the offset is not the first the run reaches it at.

  if [ "${off}" -gt 0 ]; then
    "${HC}" --stdout "${COMMON[@]}" "$@" -s $((off - 1)) -l 1 > "${win}" 2>/dev/null

    LAST_CMD="hashcat --stdout ${*} -s $((off - 1)) -l 1"
    LAST_OUT="$( head -c 2000 "${win}" )"

    if grep -q -x -F -e "${cand}" "${win}"; then
      fail_out "${label}: the window before it does not hold it" "'${cand}' absent from -s $((off - 1))"
    else
      PASS=$((PASS + 1))
    fi
  fi
}

##
## fixtures
##

printf 'alpha\nbravo\ncharlie\n' > "${WORK}/w1.txt"
printf 'one\ntwo\n'              > "${WORK}/w2.txt"

# Two dictionaries laid end to end, which is the case where an index has to name the file it landed
# in rather than only its number.
mkdir -p "${WORK}/dir"
printf 'alpha\nbravo\n'   > "${WORK}/dir/d1.txt"
printf 'charlie\ndelta\n' > "${WORK}/dir/d2.txt"

# A word no shell can pass, for the $HEX[...] spelling on the way in.
printf 'a\x01b\nplain\n' > "${WORK}/binary.txt"

printf '$1\n' > "${WORK}/one.rule"

##
## -a 3
##

note "-a 3, a mask on its own"

replay merche -a 3 '?l?l?l?l?l?l'

lookup merche -m 2000 -a 3 '?l?l?l?l?l?l'
check_has "-a 3 names the mask that reaches it" "lookup: mask ?l?l?l?l?l?l reaches it"
check_has "-a 3 counts -s in base words"        "because -a 3 counts -s in base words"
check_re  "-a 3 gives a percentage"             "^lookup: base word [0-9]+ of [0-9]+, [0-9]+\.[0-9]{4}% into the run$"

note "-a 3, a queue of masks from --increment"

replay ab7 -a 3 '?l?l?d' -i --increment-min 2

lookup ab7 -m 2000 -a 3 '?l?l?d' -i --increment-min 2
check_has "-a 3 names the round in a queue"     "lookup: round 2 of 2, mask ?l?l?d, reaches it"

# The first round holds candidates too, and its offsets are the low end of the same numbering.
replay ab -a 3 '?l?l?d' -i --increment-min 2

note "-a 3, the three ways a mask can miss"

lookup toolongforthismask -m 2000 -a 3 '?l?l?l'
check_has "a candidate longer than every mask"  "no mask in this run is that many characters long"
check_has "a length miss is still a miss"       "lookup: nothing in this run produces it"

lookup ABC -m 2000 -a 3 '?l?l?l'
check_has "a byte the mask does not allow"      "mask ?l?l?l gets furthest: position 1 wants 'A' and that mask does not allow it there"

lookup merche -m 2000 -a 3 '?l?l?l?l?l?l' -t 5
check_has "a byte --markov-threshold dropped"   "which the mask allows and --markov-threshold 5 dropped from the table"
check_has "and how to reach it after all"       "raise -t, or drop it, and that mask reaches it"

note "-a 3, what the hash mode does to the question"

# A mode that hashes in upper case has had every charset folded, so a lower case candidate has to be
# folded to match rather than reported as unreachable.
lookup abc -m 3000 -a 3 '?l?l?l'
check_has "an upper case mode folds the candidate" "this mode hashes in upper case, so every candidate in the run is, and this one was folded to match"
check_has "and then reaches it"                    "reaches it"

# A mask outside the mode's password length is not part of the run at all.
lookup ABCDEFGH -m 3000 -a 3 '?u?u?u?u?u?u?u?u?u?u'
check_has "masks outside the length are counted out" "mask(s) were passed over for being outside this mode's password length"

note "-a 3, -S counts -s in candidates"

# --stdout refuses -S ("Slow candidates (-S) is not allowed in stdout mode"), so this is the one
# offset in the suite that cannot be replayed. The wording is what is checked.
lookup merche -m 2000 -a 3 '?l?l?l?l?l?l' -S
check_has "-S is answered in candidates"        "because -S counts -s in candidates"
check_has "-S runs one candidate per offset"    "-l 1 runs the one candidate"
check_not "-S has no cell to report"            "runs the one cell of"

note "-a 3, the window given on the command line"

lookup merche -m 2000 -a 3 '?l?l?l?l?l?l' -s 209 -l 1
check_has "a window that covers the answer"     "the -s 209 -l 1 window given here covers it"

lookup merche -m 2000 -a 3 '?l?l?l?l?l?l' -s 0 -l 10
check_has "a window that misses the answer"     "the -s 0 -l 10 window given here does not cover it"

##
## -a 1, -a 6 and -a 7
##
## All three are rewritten to -a 12 before the report runs and share combi_ctx_lookup_report (), so
## this is one code path reached three ways. Each way is still worth its own check, because what
## differs is the mask built for it and which side the base word comes from.
##

note "-a 1, wordlist plus wordlist"

replay bravotwo -a 1 "${WORK}/w1.txt" "${WORK}/w2.txt"

lookup bravotwo -m 2000 -a 1 "${WORK}/w1.txt" "${WORK}/w2.txt"
check_has "-a 1 says where it cut the candidate" "cut as 5 bytes of the first wordlist and 3 of the second"
check_has "-a 1 counts -s in base words"         "because it counts -s in base words"

# The wording here is the one combi_ctx_lookup_report () actually reaches for -a 1, not the one that
# reads as if written for it. lookup->has_q is only assigned on the hit path, so a miss always takes
# the branch that speaks of a mask. Pinned as observed rather than as it ought to read.
lookup nosuchthing -m 2000 -a 1 "${WORK}/w1.txt" "${WORK}/w2.txt"
check_has "-a 1 misses when no cut works"        "no way of cutting it leaves a word this wordlist holds and a mask value beside it"

note "-a 6, wordlist plus mask"

replay bravo42 -a 6 "${WORK}/w1.txt" '?d?d'

lookup bravo42 -m 2000 -a 6 "${WORK}/w1.txt" '?d?d'
check_has "-a 6 says where it cut the candidate" "cut as 5 bytes of the wordlist and the rest from the mask"

lookup zzzzz42 -m 2000 -a 6 "${WORK}/w1.txt" '?d?d'
check_has "-a 6 misses on the wordlist half"     "no way of cutting it leaves a word this wordlist holds and a mask value beside it"

note "-a 7, mask plus wordlist"

replay 42bravo -a 7 '?d?d' "${WORK}/w1.txt"

lookup 42bravo -m 2000 -a 7 '?d?d' "${WORK}/w1.txt"
check_has "-a 7 says which side is the base word" "cut as 2 bytes of the mask and 5 of the wordlist, and the mask is the base word here"

note "-a 6, several dictionaries laid end to end"

replay charlie42 -a 6 "${WORK}/dir" '?d?d'

lookup charlie42 -m 2000 -a 6 "${WORK}/dir" '?d?d'
check_has "an index in a folder names its file"  ", in ${WORK}/dir/d2.txt,"
check_has "an index in a folder is global"       "lookup: base word 2 of 4"

note "-a 6, a queue of masks"

replay bravo7 -a 6 "${WORK}/w1.txt" '?d?d' -i --increment-min 1

lookup bravo7 -m 2000 -a 6 "${WORK}/w1.txt" '?d?d' -i --increment-min 1
check_re  "-a 6 names the round in a queue"      "^lookup: round 1 of 2, mask \?d, reaches it$"

##
## -a 0
##

note "-a 0, the wordlist is the whole attack"

replay merche03 -a 0 "${DICT}"

lookup merche03 -m 2000 -a 0 "${DICT}"
check_has "-a 0 counts -s in words"              "because -a 0 counts -s in words"
check_has "-a 0 runs one word per offset"        "-l 1 runs the one word"
check_has "-a 0 names the word index"            "lookup: word 89999 of 128416"

lookup ZZnotpresentZZ -m 2000 -a 0 "${DICT}"
check_has "a word not in the list is a proof"    "the wordlist does not hold it, and without rules the wordlist is the whole attack"

lookup '$HEX[610162]' -m 2000 -a 0 "${WORK}/binary.txt"
check_has "a \$HEX[] candidate is accepted"      "lookup: word 0 of 2"

note "-a 0, several dictionaries laid end to end"

lookup delta -m 2000 -a 0 "${WORK}/dir"
check_has "-a 0 names the file the word is in"   "lookup: word 3 of 4, in ${WORK}/dir/d2.txt"

##
## rules
##

note "a rule set is refused, not answered about the base word"

lookup merche03123 -a 0 "${DICT}" -r "${WORK}/one.rule"
check_has "-r with --lookup is refused"          "Combining -r/--rules-file or -g/--rules-generate with --lookup is not allowed."
check_has "and the refusal says why"             "A rule cannot be inverted"
check_not "no offset is given for it"            "reaches it at -s"

lookup merche03123 -a 0 "${DICT}" -g 20
check_has "-g with --lookup is refused"          "Combining -r/--rules-file or -g/--rules-generate with --lookup is not allowed."

# Refused before anything is opened, which is the point of doing it in the option check rather than
# after a pass over the wordlist.
LAST_CMD="hashcat --lookup=x -a 0 /nonexistent/wordlist -r /nonexistent/rules"
LAST_OUT="$( "${HC}" --lookup=x "${COMMON[@]}" -a 0 /nonexistent/wordlist -r /nonexistent/rules 2>&1 )"
check_has "refused before a file is opened"      "Combining -r/--rules-file or -g/--rules-generate with --lookup is not allowed."
check_not "so no file error is reported"         "No such file"

##
## end to end
##

if [ "${CRACK}" -eq 1 ]; then

  note "cracking at the offset the lookup reports"

  # A real attack takes the hash before the wordlist or the mask, which a lookup does not take at
  # all, so the attack mode and the rest of the arguments are kept apart here.

  crack_at ()
  {
    local label="$1" cand="$2" mode="$3"; shift 3

    local hash off rc

    hash="$( printf '%s' "${cand}" | md5sum | cut -d' ' -f1 )"

    lookup "${cand}" -a "${mode}" "$@"

    off="$( printf '%s\n' "${LAST_OUT}" | sed -n 's/^lookup: this run reaches it at -s \([0-9]*\),.*/\1/p' )"

    if [ -z "${off}" ]; then
      fail_out "${label}: an offset is reported" "a \"reaches it at -s N\" line"

      return 1
    fi

    # shellcheck disable=SC2086
    LAST_OUT="$( "${HC}" -m 0 -a "${mode}" -s "${off}" -l 1 --quiet "${COMMON[@]}" ${HC_OPTS} "${hash}" "$@" 2>&1 )"
    LAST_CMD="hashcat -m 0 -a ${mode} -s ${off} -l 1 ${hash} $*"

    check_has "${label}: -s ${off} -l 1 cracks it" "${cand}"

    if [ "${off}" -gt 0 ]; then
      # shellcheck disable=SC2086
      "${HC}" -m 0 -a "${mode}" -s $((off - 1)) -l 1 --quiet "${COMMON[@]}" ${HC_OPTS} "${hash}" "$@" > "${WORK}/miss.txt" 2>&1

      rc=$?

      LAST_CMD="hashcat -m 0 -a ${mode} -s $((off - 1)) -l 1 ${hash} $*"
      LAST_OUT="$( printf 'exit %d\n' "${rc}"; cat "${WORK}/miss.txt" )"

      check_has "${label}: -s $((off - 1)) -l 1 exhausts" "exit 1"
    fi
  }

  # A mask attack, where one offset is a cell of many candidates.
  crack_at "-a 3" merche 3 '?l?l?l?l?l?l'

  # A wordlist attack, where it is one word.
  crack_at "-a 0" merche03 0 "${DICT}"

  # A hybrid, where the cell is the mask side.
  crack_at "-a 6" bravo42 6 "${WORK}/w1.txt" '?d?d'
fi

##
## result
##

echo ""
echo "passed: ${PASS}"
echo "failed: ${FAIL}"

if [ "${CRACK}" -eq 0 ]; then
  echo ""
  echo "The end to end checks were not run. Add --crack, on a machine with a backend."
fi

[ "${FAIL}" -eq 0 ] || exit 1

exit 0
