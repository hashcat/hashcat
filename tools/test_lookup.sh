#!/usr/bin/env bash

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Tests --lookup for -a 0, with and without rules:
#
#   tools/test_lookup.sh            # the checks that need no device
#   tools/test_lookup.sh --crack    # and the ones that crack a hash
#   tools/test_lookup.sh --help
#
# --lookup opens no device and reads no hashes, so everything except --crack
# runs on a machine with no backend at all and is cheap enough for CI.
#
# The oracle is --stdout. It is the run's own candidate generator, so the Nth
# line it writes is the Nth candidate the run tries, and for -a 0 with R rules
# the candidate on line L comes from base word (L - 1) / R under rule
# (L - 1) % R. --lookup has to name that word and that rule, for the FIRST line
# equal to the candidate, since that is the first time the run tries it. The two
# sides share no code: --stdout walks forwards through the dispatcher and the
# kernel rule engine, --lookup searches the feed on its own.
#
# --crack adds the end to end check the oracle cannot make: that the offset
# --lookup reports is one a real attack cracks the hash at, that the word before
# it does not, and that --debug-mode names the same word and the same rule. It
# needs a working backend, so pass anything that run needs through HC_OPTS:
#
#   HC_OPTS="-D 1 --force" tools/test_lookup.sh --crack

set -u

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT="$( cd "${TDIR}/.." && pwd )"

HC="${ROOT}/hashcat"
DICT="${ROOT}/example.dict"
RULES="${ROOT}/rules/best66.rule"

# How much of example.dict the oracle runs on. The whole file would make the
# oracle stream 8.5 million lines for no more coverage; this still puts the
# answers thousands of words deep.
DICT_LINES=20000

CRACK=0
HC_OPTS="${HC_OPTS:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    -c|--crack) CRACK=1 ;;
    -h|--help)
      sed -n '8,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown option: $1, try --help"
      exit 1
      ;;
  esac
  shift
done

for f in "${HC}" "${DICT}" "${RULES}"; do
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

# A seekdb path of its own, a potfile and a logfile it does not write: a test
# leaves nothing in the tree it ran from.
COMMON=( --potfile-disable --logfile-disable --seekdb-path="${WORK}/seekdb" )

mkdir -p "${WORK}/seekdb"

PASS=0
FAIL=0

# Every check goes through these, so a failure says what was run, what was
# expected of it and what came back instead.

LAST_CMD=""
LAST_OUT=""

run_lookup ()
{
  LAST_CMD="hashcat --lookup=$*"
  LAST_OUT="$( "${HC}" --lookup="$1" "${COMMON[@]}" "${@:2}" 2>&1 )"
}

check_has ()
{
  local label="$1" needle="$2"

  if printf '%s\n' "${LAST_OUT}" | grep -qF -e "${needle}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  FAIL=$((FAIL + 1))

  echo "FAIL: ${label}"
  echo "  ran     : ${LAST_CMD}"
  echo "  expected: a line holding '${needle}'"
  echo "  got     :"
  printf '%s\n' "${LAST_OUT}" | sed 's/^/    /'
  echo ""

  return 1
}

check_not ()
{
  local label="$1" needle="$2"

  if ! printf '%s\n' "${LAST_OUT}" | grep -qF -e "${needle}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  FAIL=$((FAIL + 1))

  echo "FAIL: ${label}"
  echo "  ran     : ${LAST_CMD}"
  echo "  expected: no line holding '${needle}'"
  echo "  got     :"
  printf '%s\n' "${LAST_OUT}" | sed 's/^/    /'
  echo ""

  return 1
}

# The same two against an extended regular expression, for the checks that need
# to anchor rather than match anywhere on the line.

check_re ()
{
  local label="$1" pattern="$2"

  if printf '%s\n' "${LAST_OUT}" | grep -qE -e "${pattern}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  FAIL=$((FAIL + 1))

  echo "FAIL: ${label}"
  echo "  ran     : ${LAST_CMD}"
  echo "  expected: a line matching /${pattern}/"
  echo "  got     :"
  printf '%s\n' "${LAST_OUT}" | sed 's/^/    /'
  echo ""

  return 1
}

check_re_not ()
{
  local label="$1" pattern="$2"

  if ! printf '%s\n' "${LAST_OUT}" | grep -qE -e "${pattern}"; then
    PASS=$((PASS + 1))
    return 0
  fi

  FAIL=$((FAIL + 1))

  echo "FAIL: ${label}"
  echo "  ran     : ${LAST_CMD}"
  echo "  expected: no line matching /${pattern}/"
  echo "  got     :"
  printf '%s\n' "${LAST_OUT}" | sed 's/^/    /'
  echo ""

  return 1
}

note ()
{
  echo "## $*"
}

##
## fixtures
##

# Real words at a real depth, for the oracle.
head -n "${DICT_LINES}" "${DICT}" > "${WORK}/dict.txt"

# Small and hand held, for the checks that are about what the report says rather
# than about where it points. The duplicate is there for the without-rules path,
# which counts repeats; the last word only differs from the first by case.
printf 'alpha\nbravo\ncharlie\nalpha\nDelta\n' > "${WORK}/small.txt"

# One rule per behaviour: keep the word, append, upper case, substitute, and one
# built of several commands so the reported rule text has to hold all of them.
printf ':\n$1\nu\nsa@\nc $2 $0 $2 $5\n' > "${WORK}/five.rule"

printf '$9\n' > "${WORK}/one.rule"

# Two rule files, to be stacked into a set neither of them holds.
printf '$a\n$b\n' > "${WORK}/left.rule"
printf 'u\nc\n'   > "${WORK}/right.rule"

# A word no shell can pass and no terminal should be handed, so that both ends of
# the $HEX[...] spelling are covered: the candidate goes in as one and the base
# word comes back as one.
printf 'a\x01b\nplain\n' > "${WORK}/binary.txt"

# Several dictionaries laid end to end, which is the case where an index has to
# name the file it landed in.
mkdir -p "${WORK}/dir"
printf 'one\ntwo\n'   > "${WORK}/dir/d1.txt"
printf 'three\nfour\n' > "${WORK}/dir/d2.txt"

##
## the oracle
##

# Build the candidate stream of a run once, and answer every question about that
# run from the file.

STREAM=""
STREAM_R=0

build_stream ()
{
  local words="$1"; shift

  STREAM="${WORK}/stream.txt"

  "${HC}" --stdout "${COMMON[@]}" "$@" > "${STREAM}" 2>/dev/null

  local lines
  lines="$( wc -l < "${STREAM}" )"

  STREAM_R=$((lines / words))

  # The whole oracle rests on the run producing exactly R candidates for every
  # base word, so it is checked rather than assumed. A length filter that drops
  # a word, or a mode that adds one, breaks the arithmetic below and this says so
  # instead of letting the checks assert against nonsense.
  if [ $((STREAM_R * words)) -ne "${lines}" ]; then
    echo "FAIL: the oracle stream is ${lines} lines, which is not a whole number of rules per word over ${words} words"
    FAIL=$((FAIL + 1))
    return 1
  fi

  return 0
}

# The word and rule the stream says a candidate comes from, from the FIRST line
# equal to it. Sets ORACLE_WORD and ORACLE_RULE.

ORACLE_WORD=0
ORACLE_RULE=0

oracle ()
{
  local cand="$1" line

  line="$( grep -n -x -F -m1 -e "${cand}" "${STREAM}" | cut -d: -f1 )"

  if [ -z "${line}" ]; then
    echo "FAIL: the oracle stream does not hold '${cand}' at all"
    FAIL=$((FAIL + 1))
    return 1
  fi

  ORACLE_WORD=$(( (line - 1) / STREAM_R ))
  ORACLE_RULE=$(( (line - 1) % STREAM_R ))

  return 0
}

##
## checks
##

note "the --stdout oracle, ${DICT_LINES} words of example.dict with $( basename "${RULES}" )"

if build_stream "${DICT_LINES}" -a 0 "${WORK}/dict.txt" -r "${RULES}"; then

  # Spread through the stream: the first two candidates, the last rule of the
  # first word and the first of the second, one a few hundred words in, the
  # middle of the run and its very last candidate.
  STREAM_LINES=$(( DICT_LINES * STREAM_R ))

  for probe in 1 2 "${STREAM_R}" $((STREAM_R + 1)) 40000 $((STREAM_LINES / 2)) "${STREAM_LINES}"; do

    cand="$( sed -n "${probe}p" "${STREAM}" )"

    # Nothing here should produce one, but a candidate that is empty, that a
    # length ceiling could have cut, or that holds a byte the shell cannot carry
    # would be testing the harness rather than hashcat.
    [ -z "${cand}" ]        && continue
    [ "${#cand}" -ge 31 ]   && continue

    case "${cand}" in *[![:print:]]*) continue ;; esac

    oracle "${cand}" || continue

    run_lookup "${cand}" -a 0 "${WORK}/dict.txt" -r "${RULES}"

    check_has "line ${probe}: '${cand}' is word ${ORACLE_WORD}"  "lookup: word ${ORACLE_WORD} of ${DICT_LINES}"
    check_has "line ${probe}: '${cand}' is rule ${ORACLE_RULE}"  "and rule ${ORACLE_RULE} of ${STREAM_R} is what makes the candidate out of it"
    check_has "line ${probe}: '${cand}' is reached at -s ${ORACLE_WORD}" "this run reaches it at -s ${ORACLE_WORD},"
  done
fi

note "the same, with -O, which runs the other rule engine"

if build_stream "${DICT_LINES}" -a 0 "${WORK}/dict.txt" -r "${RULES}" -O; then

  STREAM_LINES=$(( DICT_LINES * STREAM_R ))

  for probe in 1 "${STREAM_R}" 40000 $((STREAM_LINES / 2)); do

    cand="$( sed -n "${probe}p" "${STREAM}" )"

    [ -z "${cand}" ]      && continue
    [ "${#cand}" -ge 31 ] && continue

    case "${cand}" in *[![:print:]]*) continue ;; esac

    oracle "${cand}" || continue

    run_lookup "${cand}" -a 0 "${WORK}/dict.txt" -r "${RULES}" -O

    check_has "-O line ${probe}: '${cand}' is word ${ORACLE_WORD}" "lookup: word ${ORACLE_WORD} of ${DICT_LINES}"
    check_has "-O line ${probe}: '${cand}' is rule ${ORACLE_RULE}" "and rule ${ORACLE_RULE} of ${STREAM_R} is what makes the candidate out of it"
  done
fi

note "what the report says"

# The rule that makes the candidate is named by its text, not only by its number,
# and the text has to survive a rule of several commands.
run_lookup "Alpha2025" -a 0 "${WORK}/small.txt" -r "${WORK}/five.rule"
check_has "a multi command rule is spelled out" "rule 4 of 5 is what makes the candidate out of it: c \$2 \$0 \$2 \$5"
check_has "the base word is named"              "that word is 'alpha'"
check_has "the word index is the first alpha"   "lookup: word 0 of 5"

# The fourth word is 'alpha' again, so a candidate only that copy could make does
# not exist. What this checks is that the search reports the FIRST word that
# makes the candidate and not the last.
run_lookup "alpha1" -a 0 "${WORK}/small.txt" -r "${WORK}/five.rule"
check_has "a repeated word answers with its first copy" "lookup: word 0 of 5"

# A rule set of one is a rule set, and reads as one.
run_lookup "bravo9" -a 0 "${WORK}/small.txt" -r "${WORK}/one.rule"
check_has "one rule is named as one rule"       "rule 0 of 1 is what makes the candidate out of it: \$9"
check_has "one rule is not counted as 'all 1'"  "with the one rule applied to it"

# Two -r files are one rule set of their product, and no rule in either file
# makes this on its own.
run_lookup "ALPHAB" -a 0 "${WORK}/small.txt" -r "${WORK}/left.rule" -r "${WORK}/right.rule"
check_has "stacked rules are one set of 4"    "of 4 is what makes the candidate out of it"
check_has "stacked rules report the stack"    "\$b u"

note "a miss with rules is a proof"

run_lookup "ZZnotpresentZZ" -a 0 "${WORK}/small.txt" -r "${WORK}/five.rule"
check_has "a miss with rules is stated as one" "nothing in this run produces it. every one of the 5 words was tried with all 5 rules and none of them makes it"
check_not "a miss with rules no longer hedges" "NOT checked"
check_not "a miss with rules is not called unprovable" "not a proof"

# The word itself is in the list, but no rule leaves it as it is, so the run
# never tries it. This is the case the word-only search used to answer wrongly.
run_lookup "charlie" -a 0 "${WORK}/small.txt" -r "${WORK}/one.rule"
check_has "a word no rule leaves alone is a miss" "nothing in this run produces it"

note "without rules, unchanged"

run_lookup "charlie" -a 0 "${WORK}/small.txt"
check_has "a word with no rules is found"     "lookup: word 2 of 5"
check_not "a word with no rules names no rule" "is what makes the candidate out of it"

run_lookup "alpha" -a 0 "${WORK}/small.txt"
check_has "a repeated word is counted"        "it is in this wordlist 1 more times"

run_lookup "ZZnotpresentZZ" -a 0 "${WORK}/small.txt"
check_has "a miss with no rules is a proof"   "the wordlist does not hold it, and without rules the wordlist is the whole attack"

note "candidates and words no shell can pass"

# In as $HEX[...], because the candidate holds a byte a command line cannot. The
# bytes are a\x01b with a 1 appended, which is what the second of the five rules
# makes of the first word.
run_lookup '$HEX[61016231]' -a 0 "${WORK}/binary.txt" -r "${WORK}/five.rule"
check_has "a \$HEX[] candidate is accepted"   "lookup: word 0 of 2"
check_has "a \$HEX[] candidate names its rule" "rule 1 of 5 is what makes the candidate out of it: \$1"

# And back out as $HEX[...], because the base word does too.
printf '$z\n' > "${WORK}/z.rule"
run_lookup '$HEX[6101627a]' -a 0 "${WORK}/binary.txt" -r "${WORK}/z.rule"
check_has "a base word that needs hex is written as hex" "that word is '\$HEX[610162]'"

note "several dictionaries"

run_lookup "four9" -a 0 "${WORK}/dir" -r "${WORK}/one.rule"
check_has "an index in a folder names its file" "of 4, in ${WORK}/dir/d2.txt"
check_has "an index in a folder is global"      "lookup: word 3 of 4"

note "the window, and where the answer sits in the run"

run_lookup "four9" -a 0 "${WORK}/dir" -r "${WORK}/one.rule" -s 3 -l 1
check_has "a window that covers the answer says so"     "the -s 3 -l 1 window given here covers it"

run_lookup "four9" -a 0 "${WORK}/dir" -r "${WORK}/one.rule" -s 0 -l 2
check_has "a window that misses the answer says so"     "the -s 0 -l 2 window given here does not cover it"

run_lookup "four9" -a 0 "${WORK}/dir" -r "${WORK}/one.rule"
check_has "the answer is given as a fraction of the run" "75.0000% into the run"

note "generated rules"

# -g leaves a slot empty where a rule it made did not convert, and an empty slot
# is a rule that changes nothing. Whatever it lands on, the report must name a
# word and a rule and must not print a rule as a blank.
run_lookup "alpha" -a 0 "${WORK}/small.txt" -g 20 --generate-rules-seed 1
check_has "-g answers with a word"       "lookup: word 0 of 5"
check_has "-g answers with a rule"       "of 20 is what makes the candidate out of it"
check_re_not "-g never prints a blank rule" "out of it: *$"

note "a word longer than the rule engine can hold"

# 35 bytes, which is past what -O keeps a candidate in.
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > "${WORK}/long.txt"
printf ':\n'   > "${WORK}/noop.rule"
printf '$1\n' > "${WORK}/append.rule"

# What the run does with it, established rather than assumed: -O rejects a base
# word that long before any rule touches it, so the run produces nothing at all
# from this wordlist.
produced="$( "${HC}" --stdout "${COMMON[@]}" -a 0 "${WORK}/long.txt" -r "${WORK}/noop.rule" -O 2>/dev/null | wc -l )"

LAST_CMD="hashcat --stdout -a 0 long.txt -r noop.rule -O"
LAST_OUT="${produced}"
check_re "-O builds nothing from a 35 byte word" "^0$"

# So there is nothing for --lookup to find either. Cutting the word to 31 bytes
# to fit the engine would answer about a candidate the run never builds, and the
# rule here is the one that keeps the word, so a cut would be reported as a hit.
run_lookup "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" -a 0 "${WORK}/long.txt" -r "${WORK}/noop.rule" -O
check_has "-O does not cut a long word to fit" "nothing in this run produces it"

# The same word without -O is inside what the pure engine holds, so it is found.
run_lookup "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1" -a 0 "${WORK}/long.txt" -r "${WORK}/append.rule"
check_has "the pure engine holds the same word" "lookup: word 0 of 1"

##
## end to end
##

if [ "${CRACK}" -eq 1 ]; then

  note "cracking at the offset the lookup reports"

  # A word deep in the dictionary, and a candidate some rule makes of it. Which
  # rule is not chosen here: that is what --lookup is being asked.
  WORD="$( sed -n '18000p' "${WORK}/dict.txt" )"
  CAND="${WORD}123"

  printf '%s' "${CAND}" | md5sum | cut -d' ' -f1 > "${WORK}/hash.txt"

  run_lookup "${CAND}" -a 0 "${WORK}/dict.txt" -r "${RULES}"

  SKIP="$( printf '%s\n' "${LAST_OUT}" | sed -n 's/^lookup: this run reaches it at -s \([0-9]*\),.*/\1/p' )"
  RULE="$( printf '%s\n' "${LAST_OUT}" | sed -n "s/^lookup: that word is '.*', and rule [0-9]* of [0-9]* is what makes the candidate out of it: //p" )"

  if [ -z "${SKIP}" ]; then
    echo "FAIL: no offset was reported for '${CAND}', so there is nothing to crack at"
    FAIL=$((FAIL + 1))
  else
    # shellcheck disable=SC2086
    "${HC}" -m 0 -a 0 -s "${SKIP}" -l 1 --quiet --debug-mode=4 --debug-file="${WORK}/debug.txt" \
      "${COMMON[@]}" ${HC_OPTS} "${WORK}/hash.txt" "${WORK}/dict.txt" -r "${RULES}" > "${WORK}/crack.txt" 2>&1

    LAST_CMD="hashcat -m 0 -a 0 -s ${SKIP} -l 1 ... -r $( basename "${RULES}" )"
    LAST_OUT="$( cat "${WORK}/crack.txt" "${WORK}/debug.txt" 2>/dev/null )"

    check_has "-s ${SKIP} -l 1 cracks it"                "${CAND}"
    check_has "the debug file names the same base word"  "${WORD}:"
    check_has "the debug file names the reported rule"   "${WORD}:${RULE}:${CAND}"

    # One word earlier must not reach it, or the offset is not the first the run
    # tries it at and --lookup has pointed too far in.
    # shellcheck disable=SC2086
    "${HC}" -m 0 -a 0 -s $((SKIP - 1)) -l 1 --quiet \
      "${COMMON[@]}" ${HC_OPTS} "${WORK}/hash.txt" "${WORK}/dict.txt" -r "${RULES}" > "${WORK}/miss.txt" 2>&1

    rc=$?

    LAST_CMD="hashcat -m 0 -a 0 -s $((SKIP - 1)) -l 1 ..."
    LAST_OUT="$( printf 'exit %d\n' "${rc}"; cat "${WORK}/miss.txt" )"

    check_has "-s $((SKIP - 1)) -l 1 exhausts without cracking it" "exit 1"
  fi
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
