#!/usr/bin/env bash
#
# Write the seed corpora for the fuzz targets.
#
# Both corpora are built out of the tree itself, so they cost nothing to carry
# and they stay in step with what hashcat accepts: the rules ship in rules/ and
# the example hash of every mode is the ST_HASH in its module.
#
# Usage:
#   tools/fuzz/seeds.sh <outdir>
#
# Writes <outdir>/rule and <outdir>/tokenizer, one input per file.

set -eu

OUTDIR=${1:-}

if [ -z "$OUTDIR" ]; then
  echo "usage: tools/fuzz/seeds.sh <outdir>" >&2
  exit 2
fi

if [ ! -f src/rp.c ]; then
  echo "error: run this from the hashcat source root" >&2
  exit 2
fi

rm -rf "${OUTDIR}/rule" "${OUTDIR}/tokenizer"
mkdir -p "${OUTDIR}/rule" "${OUTDIR}/tokenizer"

python3 - "$OUTDIR" <<'PY'
import glob
import hashlib
import os
import re
import sys

outdir = sys.argv[1]

# 1. rules. A handful of files rather than all of them: the big generated ones
# repeat the same commands with different operands, which the fuzzer varies far
# better than a corpus can. What matters is that every command appears.

RULE_FILES = [
    "rules/best66.rule",
    "rules/combinator.rule",
    "rules/leetspeak.rule",
    "rules/oscommerce.rule",
    "rules/specific.rule",
    "rules/toggles1.rule",
    "rules/toggles2.rule",
    "rules/top10_2025.rule",
    "rules/InsidePro-PasswordsPro.rule",
]

seen = set()
written = 0

for path in RULE_FILES:
    if not os.path.exists(path):
        continue

    with open(path, "rb") as fh:
        for line in fh:
            line = line.rstrip(b"\r\n")

            if not line or line.startswith(b"#"):
                continue

            if line in seen:
                continue

            seen.add(line)

            name = hashlib.sha1(line).hexdigest()[:16]

            with open(os.path.join(outdir, "rule", name), "wb") as out:
                out.write(line)

            written += 1

print("seeds: %d rules" % written)

# 2. tokenizer. Every input carries its own token spec, so a seed is that
# header followed by an example hash. The header asks for as many tokens as the
# line has fields, split on the separator the line actually uses, with no
# attribute set and no length limit that would reject the line before it is
# split. From there the fuzzer varies the spec and the line together.

MAX_FUZZ_TOKENS = 8

def header(token_cnt, sep):
    out = bytearray()
    out.append(token_cnt - 1)   # the target reads this modulo MAX_FUZZ_TOKENS
    out.append(0)               # signature "$test$", unused while no token verifies one

    for _ in range(token_cnt):
        out += b"\x00\x00"      # attributes
        out.append(sep)         # separator
        out.append(0)           # len_min
        out.append(255)         # len_max, as an offset above len_min

    return bytes(out)

written = 0

for path in sorted(glob.glob("src/modules/module_*.c")):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()

    match = re.search(r'static const char \*ST_HASH\s*=\s*"((?:[^"\\]|\\.)*)"', source)

    if match is None:
        continue

    try:
        line = match.group(1).encode("utf-8").decode("unicode_escape").encode("latin1")
    except (UnicodeDecodeError, UnicodeEncodeError):
        continue

    if not line:
        continue

    for sep in (b":", b"$", b"*"):
        fields = line.count(sep) + 1

        if fields < 2:
            continue

        token_cnt = min(fields, MAX_FUZZ_TOKENS)

        seed = header(token_cnt, sep[0]) + line

        name = hashlib.sha1(seed).hexdigest()[:16]

        with open(os.path.join(outdir, "tokenizer", name), "wb") as out:
            out.write(seed)

        written += 1

print("seeds: %d tokenizer inputs" % written)
PY
