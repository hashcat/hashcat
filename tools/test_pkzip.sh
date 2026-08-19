#!/usr/bin/env bash
#
# PKZIP real-container validator.
#
# Cross-checks hashcat's traditional-PKZIP modes (17200/17210/17220/17225/17230)
# against GENUINE archives produced by InfoZip's `zip`, extracted with John's
# `zip2john`. This is the ground-truth complement to the self-contained test.pl
# oracles in tools/test_modules/m172*.pm: those prove hashcat agrees with our
# own ZipCrypto, this proves it agrees with a real-world ZIP toolchain.
#
# Dependencies (override via env):
#   ZIP       - InfoZip `zip`      (default: zip on PATH)
#   ZIP2JOHN  - John's zip2john    (default: /home/user/john/run/zip2john)
#   HASHCAT   - hashcat binary     (default: ./hashcat)
#
# Usage: tools/pkzip_realzip_validate.sh [password]
#
set -u

ZIP="${ZIP:-zip}"
ZIP2JOHN="${ZIP2JOHN:-/home/user/john/run/zip2john}"
HASHCAT="${HASHCAT:-./hashcat}"
PW="${1:-hashcat}"

for t in "$ZIP" "$ZIP2JOHN" "$HASHCAT"; do
  command -v "$t" >/dev/null 2>&1 || [ -x "$t" ] || { echo "missing tool: $t"; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FILES="$WORK/files"; mkdir -p "$FILES"

# a few compressible text files + one incompressible blob (forces a stored entry)
for i in 1 2 3 4; do
  python3 - "$FILES/t$i.txt" "$i" <<'PY'
import sys
open(sys.argv[1], "w").write(("pattern %s the quick brown fox " % sys.argv[2]) * 400)
PY
done
head -c 64 /dev/urandom > "$FILES/rand.bin"

echo "$PW" > "$WORK/pw.txt"

extract() { "$ZIP2JOHN" ${2:-} "$1" 2>/dev/null | sed -E 's/^[^:]*://' | grep -oE '^\$pkzip2?\$[^:]+' | head -1; }

# build the container matrix: label -> hashcat mode -> zip invocation [-> zip2john flag]
declare -a ROWS=(
  "stored-single|17210|-0 -e|"
  "deflate-single|17200|-9 -e|"
  "deflate-multi|17220|-9 -e|MULTI"
  "mixed-multi|17225|-e|MIXED"
  "checksum-only|17230|-9 -e|CKSUM"
)

pass=0; fail=0
printf "%-16s %-7s %-9s %s\n" "container" "mode" "files" "result"
printf -- "----------------------------------------------------\n"

for row in "${ROWS[@]}"; do
  IFS='|' read -r label mode zflags special <<<"$row"
  zf="$WORK/$label.zip"; rm -f "$zf"

  case "$special" in
    MULTI) inputs=("$FILES/t1.txt" "$FILES/t2.txt" "$FILES/t3.txt") ;;
    MIXED) inputs=("$FILES/t1.txt" "$FILES/rand.bin" "$FILES/t2.txt") ;;
    CKSUM) inputs=("$FILES/t1.txt" "$FILES/t2.txt" "$FILES/t3.txt" "$FILES/t4.txt") ;;
    *)     inputs=("$FILES/t1.txt") ;;
  esac

  "$ZIP" $zflags -P "$PW" "$zf" "${inputs[@]}" >/dev/null 2>&1

  j2jflag=""
  [ "$special" = "CKSUM" ] && j2jflag="-c"
  hash="$(extract "$zf" "$j2jflag")"

  nfiles="${#inputs[@]}"
  if [ -z "$hash" ]; then
    printf "%-16s %-7s %-9s %s\n" "$label" "$mode" "$nfiles" "NO-HASH"; fail=$((fail+1)); continue
  fi
  echo "$hash" > "$WORK/h.txt"

  find kernels -name "*$mode*" -delete 2>/dev/null
  rm -f "$WORK/o.txt"
  # </dev/null: hashcat's interactive keypress thread reads the terminal; run
  # from a script with no controlling tty that read raises SIGTTIN and the
  # process is suspended (state T) until timeout kills it. Feed it EOF instead.
  timeout 180 "$HASHCAT" -m "$mode" -a 0 --self-test-disable --potfile-disable \
      -d 1 --quiet -o "$WORK/o.txt" "$WORK/h.txt" "$WORK/pw.txt" </dev/null >/dev/null 2>&1

  if [ -s "$WORK/o.txt" ]; then
    printf "%-16s %-7s %-9s %s\n" "$label" "$mode" "$nfiles" "CRACKED"; pass=$((pass+1))
  else
    printf "%-16s %-7s %-9s %s\n" "$label" "$mode" "$nfiles" "FAILED (investigate)"; fail=$((fail+1))
  fi
done

printf -- "----------------------------------------------------\n"
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
