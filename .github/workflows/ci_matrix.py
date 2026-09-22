#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Works out what .github/workflows/test.yml and fuzz.yml run, as a job matrix.
##
##   ci_matrix.py test|fuzz pr <base>       the modes a pull request touches
##   ci_matrix.py test|fuzz all             every mode, sharded
##   ci_matrix.py test|fuzz list "<modes>"  the modes named, for a manual run
##
## Writes run=, matrix= and summary= lines for $GITHUB_OUTPUT. A mode lands in
## the shard its number hashes to, so a mode keeps its shard, and with it its
## fuzz corpus, when modes are added or removed elsewhere. Not mode % SHARDS,
## because most modes are a multiple of 100 and four shards would get them all.

import json
import os
import re
import subprocess
import sys
import zlib

SHARDS = 16

# A pull request is bounded by this many modes. Past it the rest is left to the
# weekly run, and the summary says which were left out.

PR_MODE_CAP = {"test": 30, "fuzz": 20}

# A PR that touches shared code, but no mode of its own, still gets a run:
# test.sh -M for the kernels, and the starting set of parser targets for fuzz.

FUZZ_DEFAULT_MODES = [7400, 17225, 22000, 29100]

# The host files the fuzz targets link, which is the CORE list in
# tools/fuzz/build.sh, plus what builds and drives them.

FUZZ_SHARED = re.compile(r"^(src/(rp|rp_cpu|parser|memory|convert|shared|paw64|timer|bitops|cpu_crc32|"
                         r"keyboard_layout|ext_lzma|ext_zlib|dynloader|folder|path|plugin_abi|emu_[a-z0-9_]+)\.c"
                         r"|include/.*|tools/fuzz/.*|tools/asan/hashconfig\.[ch]"
                         r"|\.github/workflows/(fuzz\.yml|ci_matrix\.py))$")

# Everything test.sh builds on or runs through that does not belong to one mode.

TEST_SHARED = re.compile(r"^(OpenCL/.*|src/.*|include/.*|deps/.*|Makefile|tools/test\.sh"
                         r"|tools/test_module_runner\.(pl|py)|tools/test_modules/lib/.*"
                         r"|tools/install_modules\.sh|tools/requirements\.txt"
                         r"|\.github/workflows/(test\.yml|ci_matrix\.py))$")

MODE_OF = {
    "test": [re.compile(r"^src/modules/module_(\d{5})\.c$"),
             re.compile(r"^OpenCL/m(\d{5})[-_.]"),
             re.compile(r"^tools/test_modules/m(\d{5})\.(pm|py)$")],
    "fuzz": [re.compile(r"^src/modules/module_(\d{5})\.c$")],
}


def modes_on_disk(kind):
    modes = set()

    for name in os.listdir("src/modules"):
        m = re.fullmatch(r"module_(\d{5})\.c", name)

        if m:
            modes.add(int(m.group(1)))

    if kind == "test":
        tested = set()

        for name in os.listdir("tools/test_modules"):
            m = re.fullmatch(r"m(\d{5})\.(pm|py)", name)

            if m:
                tested.add(int(m.group(1)))

        modes &= tested

    return modes


def changed_files(base):
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"],
                         check=True, capture_output=True, text=True).stdout

    return [line for line in out.splitlines() if line]


def shard_of(mode):
    return zlib.crc32(str(mode).encode()) % SHARDS


def entries(kind, modes, rule_tok):
    """One matrix entry per shard that has something to run."""

    by_shard = {}

    for mode in sorted(modes):
        by_shard.setdefault(shard_of(mode), []).append(mode)

    if kind == "fuzz" and rule_tok:
        by_shard.setdefault(0, [])

    out = []

    for shard in sorted(by_shard):
        entry = {"name": f"shard-{shard}", "shard": shard,
                 "modes": " ".join(f"{m:05d}" if kind == "fuzz" else str(m) for m in by_shard[shard])}

        if kind == "fuzz":
            entry["rule_tok"] = rule_tok and shard == 0

        out.append(entry)

    return out


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("test", "fuzz") or sys.argv[2] not in ("pr", "all", "list"):
        sys.exit(__doc__ or "usage: ci_matrix.py test|fuzz pr <base> | all | list \"<modes>\"")

    kind, scope = sys.argv[1], sys.argv[2]

    pool = modes_on_disk(kind)

    matrix = []
    notes = []

    if scope == "all":
        matrix = entries(kind, pool, True)
        notes.append(f"all {len(pool)} modes in {len(matrix)} shards")

    elif scope == "list":
        asked = {int(m) for m in re.findall(r"\d+", sys.argv[3] if len(sys.argv) > 3 else "")}

        if asked - pool:
            notes.append("not testable here, skipped: " + " ".join(str(m) for m in sorted(asked - pool)))

        matrix = entries(kind, asked & pool, kind == "fuzz")
        notes.append(f"{len(asked & pool)} modes named")

    else:
        files = changed_files(sys.argv[3])

        impacted = set()
        shared = False

        for path in files:
            hit = False

            for rx in MODE_OF[kind]:
                m = rx.match(path)

                if m:
                    impacted.add(int(m.group(1)))
                    hit = True

            if not hit and (FUZZ_SHARED if kind == "fuzz" else TEST_SHARED).match(path):
                shared = True

        impacted &= pool

        cap = PR_MODE_CAP[kind]

        if len(impacted) > cap:
            left = sorted(impacted)[cap:]
            impacted = set(sorted(impacted)[:cap])
            notes.append(f"{len(left)} more impacted modes left to the weekly run: " + " ".join(map(str, left)))

        if kind == "fuzz":
            if shared:
                impacted |= set(FUZZ_DEFAULT_MODES) & pool

            matrix = entries(kind, impacted, shared)
        else:
            matrix = entries(kind, impacted, False)

            if shared:
                matrix.append({"name": "minimal", "shard": -1, "modes": "minimal"})

        notes.append(f"{len(impacted)} impacted modes" + (", shared code changed" if shared else ""))

    print(f"run={'true' if matrix else 'false'}")
    print("matrix=" + json.dumps({"include": matrix}, separators=(",", ":")))
    print("summary=" + "; ".join(notes))


if __name__ == "__main__":
    main()
