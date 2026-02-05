#!/usr/bin/env bash

LOG=a0_optimalization_all_$(date +%Y%m%d_%H%M%S).log

echo "git rev-parse HEAD: $(git rev-parse HEAD)" | tee -a "$LOG"

modes=$(./hashcat --example-hashes --machine-readable --quiet | jq -r 'keys[]' | sort -n)

for m in $modes; do
  ./hashcat --potfile-disable --example-hashes -m $m --machine-readable --quiet | jq -r '.[].example_hash' > $m.hash

  a=$(./hashcat --potfile-disable -a0 -m$m $m.hash ./rockyou.txt -r rules/best66.rule -w4 -O -S --status --status-timer=3 --runtime=15 --quiet --status-json 2>/dev/null \
    | jq -r '.devices[0].speed // 0' \
    | tail -n3 \
    | python3 -c 'import sys; vals=[float(l.strip()) for l in sys.stdin if l.strip()]; print(int(round(sum(vals)/len(vals),0)) if vals else 0)')

  b=$(./hashcat --potfile-disable --length-bucket -a0 -m$m $m.hash ./rockyou.txt -r rules/best66.rule -w4 -O -S --status --status-timer=3 --runtime=15 --quiet --status-json 2>/dev/null \
    | jq -r '.devices[0].speed // 0' \
    | tail -n3 \
    | python3 -c 'import sys; vals=[float(l.strip()) for l in sys.stdin if l.strip()]; print(int(round(sum(vals)/len(vals),0)) if vals else 0)')

  speedup=$(python3 -c 'import sys; a=int(sys.argv[1]); b=int(sys.argv[2]); print(int(round((b/a-1)*100,0)) if a>0 else 0)' "$a" "$b")
  gt50=$(python3 -c 'import sys; a=int(sys.argv[1]); b=int(sys.argv[2]); print(1 if a>0 and b >= a*1.5 else 0)' "$a" "$b")

  block=$(printf "mode %s\n%s a0\t=\t%s H/s\n%s a0 sort\t=\t%s H/s\n%s speedup\t=\t%s%%\n" \
    "$m" "$m" "$a" "$m" "$b" "$m" "$speedup")

  if [[ "$gt50" == "1" ]]; then
    block+=$(printf "%s speedup > 50%\n" "$m")
  fi

  block+=$'\n'

  printf "%s" "$block" >> "$LOG"

  if [[ "$gt50" == "1" ]]; then
    printf "%s" "$block"
  fi
done
