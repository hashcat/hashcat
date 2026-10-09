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

# test.py takes about 100 minutes on the largest of 16 shards on a 12 core laptop, which on a 4 core
# runner is too close to the 330 minute job limit, so it gets three times the shards fuzz does

SHARDS = {"test": 48, "fuzz": 16}

# A pull request is bounded by this many modes. Past it the rest is left to the
# weekly run, and the summary says which were left out.

PR_MODE_CAP = {"test": 30, "fuzz": 20}

# A shared-code test change runs the -M set, 24 representative modes (test.py handles the container
# families now, so they go through the normal per-mode path). Run in one job it is ~17 minutes, so
# split it into shards balanced by a rough per-mode cost: the container and slow-KDF modes dominate,
# 14600 most of all because it loops ~72 LUKS files. Anything unlisted costs 1.

MINIMAL_MODES  = [0, 100, 110, 400, 500, 2600, 3000, 3200, 6211, 11600, 12500, 13711, 14200, 14511,
                  14600, 14900, 15400, 15700, 20510, 22000, 29511, 33000, 33500, 34100]
MINIMAL_WEIGHT = {14600: 12, 13711: 6, 3200: 4, 34100: 3, 29511: 3, 6211: 2, 14511: 2, 400: 2, 500: 2}
MINIMAL_SHARDS = 6


def minimal_shards(n):
    """Longest-processing-time bin-packing of MINIMAL_MODES into n shards balanced by MINIMAL_WEIGHT,
    so the one heavy mode (14600) lands alone rather than stretching a shard it shares."""
    bins = [[] for _ in range(n)]
    load = [0] * n

    for mode in sorted(MINIMAL_MODES, key=lambda m: MINIMAL_WEIGHT.get(m, 1), reverse=True):
        i = load.index(min(load))
        bins[i].append(mode)
        load[i] += MINIMAL_WEIGHT.get(mode, 1)

    return [sorted(b) for b in bins if b]


# How a PR spreads its impacted test modes across shards. A host-engine mode hashes on the CPU
# (ATTACK_EXEC_OUTSIDE_KERNEL: the container, wallet and document families), which dominates the time
# on a GPU-less runner, and the heavier MINIMAL_WEIGHT kernels (bcrypt, scrypt, LUKS, argon) cost
# almost as much. Two of those landing in one shard is what overran the 90 minute PR timeout, so each
# heavy mode gets a shard to itself while the light ones bundle, this many at a time, to still share a
# build. The shard a mode lands in is not stable here, unlike the crc32 placement entries () uses, but
# a test shard carries no per-shard state that needs to be, so balancing wins.
PR_LIGHT_PER_SHARD = 8

_HOST_ENGINE = {}


def host_engine(mode):
    # True when the module hashes on the host rather than in the kernel, read off the module source the
    # way tools/test.py does. Cached, since a PR asks about several.
    if mode not in _HOST_ENGINE:
        try:
            with open("src/modules/module_%05d.c" % mode, "rb") as fh:
                _HOST_ENGINE[mode] = b"ATTACK_EXEC_OUTSIDE_KERNEL" in fh.read()
        except OSError:
            _HOST_ENGINE[mode] = False

    return _HOST_ENGINE[mode]


def mode_weight(mode):
    # Cost estimate for balancing shards. A host-engine mode runs its KDF on the CPU and dominates on a
    # GPU-less runner; the MINIMAL_WEIGHT entries carry the known slow kernels (bcrypt, scrypt, LUKS,
    # argon) at their measured weight. Everything else is light.
    if mode in MINIMAL_WEIGHT:
        return MINIMAL_WEIGHT[mode]

    return 6 if host_engine(mode) else 1


def is_heavy(mode):
    # Slow enough that two of them in one PR shard risk the 90 minute timeout.
    return mode_weight(mode) >= 3


def pr_test_shards(modes):
    """Spread a PR's impacted test modes so no shard runs two heavy modes. Each heavy mode gets a shard
    of its own; the light ones are chunked, so the fast modes still amortize one build across a shard."""
    heavy = sorted(m for m in modes if is_heavy(m))
    light = sorted(m for m in modes if not is_heavy(m))

    shards = [[m] for m in heavy]

    for i in range(0, len(light), PR_LIGHT_PER_SHARD):
        shards.append(light[i:i + PR_LIGHT_PER_SHARD])

    return shards


def balance_shards(modes, n):
    """Longest-processing-time bin-packing of modes into n shards by mode_weight, so the heavy modes
    spread across the shards instead of piling into whichever one crc32 happened to draw them to. For
    the weekly all-mode test run, which must bundle (far more modes than shards) and keeps no per-shard
    state that a stable hash placement would protect."""
    bins = [[] for _ in range(n)]
    load = [0] * n

    for mode in sorted(modes, key=lambda m: (mode_weight(m), m), reverse=True):
        i = load.index(min(load))
        bins[i].append(mode)
        load[i] += mode_weight(mode)

    return [sorted(b) for b in bins if b]


def test_matrix(groups, kinds):
    # One matrix entry per shard of modes and kernel kind. kinds is a subset of ("opt", "pure"): the
    # test job runs the optimized kernels for "opt" and the pure kernels for "pure". The two kinds
    # are separate parallel jobs rather than two passes in one, so running both does not add the
    # pure time on top of the opt time in a single shard. The shard number is only a label here
    # (unlike fuzz, which keys its corpus off it); the kind is appended to the name so the two jobs
    # of a shard are told apart in the run list.
    return [{"name": "shard-%d-%s" % (i, kind), "shard": i, "kind": kind,
             "modes": " ".join(str(m) for m in group)}
            for kind in kinds
            for i, group in enumerate(groups)]

# A PR that touches shared code, but no mode of its own, still gets a run:
# test.py -M for the kernels, and the starting set of parser targets for fuzz.
# That starting set is FUZZ_MODES in tools/fuzz/build.sh, where the reason for
# each mode is written down, and it is read from there so the two cannot drift.

def fuzz_default_modes():
    with open("tools/fuzz/build.sh") as fh:
        m = re.search(r'^FUZZ_MODES=\$\{FUZZ_MODES:-"([0-9 ]+)"\}', fh.read(), re.M)

    if m is None:
        sys.exit("ci_matrix.py: no FUZZ_MODES default found in tools/fuzz/build.sh")

    return [int(x) for x in m.group(1).split()]


FUZZ_DEFAULT_MODES = fuzz_default_modes()

# The host files the fuzz targets link, which is the CORE list in
# tools/fuzz/build.sh, plus what builds and drives them.

FUZZ_SHARED = re.compile(r"^(src/(rp|rp_cpu|parser|memory|convert|shared|paw64|timer|bitops|cpu_crc32|"
                         r"keyboard_layout|ext_lzma|ext_zlib|dynloader|folder|path|plugin_abi|emu_[a-z0-9_]+)\.c"
                         r"|include/.*|tools/fuzz/.*|tools/asan/hashconfig\.[ch]"
                         r"|\.github/workflows/(fuzz\.yml|fuzz_report\.py|ci_matrix\.py))$")

# Everything test.py builds on or runs through that does not belong to one mode.

TEST_SHARED = re.compile(r"^(OpenCL/.*|src/.*|include/.*|deps/.*|Makefile|tools/test\.py"
                         r"|tools/test_module_runner\.py|tools/test_modules/lib/.*"
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


def shard_of(kind, mode):
    return zlib.crc32(str(mode).encode()) % SHARDS[kind]


def entries(kind, modes, rule_tok):
    """One matrix entry per shard that has something to run."""

    by_shard = {}

    for mode in sorted(modes):
        by_shard.setdefault(shard_of(kind, mode), []).append(mode)

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
        sys.exit(__doc__ or "usage: ci_matrix.py test|fuzz pr <base> | all | list \"<modes>\" [--kinds opt,pure,bridge]")

    kind, scope = sys.argv[1], sys.argv[2]

    pool = modes_on_disk(kind)

    # A test all/list run covers up to three kinds, as parallel jobs per shard: "opt" and "pure" run
    # the mode's optimized and pure kernels, and "bridge" cracks the mode's own test oracle through
    # the Python bridge (tools/test_bridge.py), so the parser and candidate handling are checked
    # against the reference implementation with no mode kernel. --kinds picks the subset to emit,
    # which is how a manual dispatch selects kinds with its checkboxes; it defaults to all three. A
    # fuzz run has no kinds, and a pull request stays optimized only whatever is passed.
    test_kinds = ["opt", "pure", "bridge"]

    if "--kinds" in sys.argv:
        i = sys.argv.index("--kinds")
        chosen = set(sys.argv[i + 1].split(",")) if i + 1 < len(sys.argv) else set()
        test_kinds = [k for k in ("opt", "pure", "bridge") if k in chosen] or test_kinds

    matrix = []
    notes = []

    if scope == "all":
        if kind == "test":
            matrix = test_matrix(balance_shards(pool, SHARDS["test"]), test_kinds)
        else:
            matrix = entries(kind, pool, True)

        notes.append(f"all {len(pool)} modes in {len(matrix)} shards")

    elif scope == "list":
        asked = {int(m) for m in re.findall(r"\d+", sys.argv[3] if len(sys.argv) > 3 else "")}

        if asked - pool:
            notes.append("not testable here, skipped: " + " ".join(str(m) for m in sorted(asked - pool)))

        if kind == "test":
            matrix = test_matrix(balance_shards(asked & pool, SHARDS["test"]), test_kinds)
        else:
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
                    mode = int(m.group(1))

                    impacted.add(mode)

                    # Only a mode the suite can still run counts as covering this file. OpenCL/m72000-pure.cl
                    # names a mode that no longer exists, and mode 74000 is what loads that kernel now, so
                    # attributing the file to 72000 and letting the pool drop it again would test nothing.

                    if mode in pool:
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
            # A pull request stays optimized only, to keep its latency unchanged; the pure and
            # bridge kinds are left to the weekly and manual runs.
            matrix = test_matrix(pr_test_shards(impacted), ["opt"])

            if shared:
                for i, shard in enumerate(minimal_shards(MINIMAL_SHARDS)):
                    matrix.append({"name": f"minimal-{i}-opt", "shard": -1, "kind": "opt",
                                   "modes": " ".join(str(m) for m in shard)})

        note = f"{len(impacted)} impacted modes"

        if shared:
            note += (f", minimal full-test (test.py -M) in {MINIMAL_SHARDS} shards"
                     if kind == "test" else ", shared code changed")

        notes.append(note)

    print(f"run={'true' if matrix else 'false'}")
    print("matrix=" + json.dumps({"include": matrix}, separators=(",", ":")))
    print("summary=" + "; ".join(notes))


if __name__ == "__main__":
    main()
