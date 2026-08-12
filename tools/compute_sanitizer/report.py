#!/usr/bin/env python3
"""Aggregates past tools/compute_sanitizer/run.py runs into a table.

Usage:
  report.py                    # all standalone runs in results/
  report.py --test NAME        # filter by test name
  report.py --failed           # only runs with primary findings or a wrapper failure
  report.py --latest N         # last N, after other filters
  report.py --dir <sweep-dir>  # a test.sh/test_edge.sh sweep's own results directory
"""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = SCRIPT_DIR / "results"


def load_runs(base):
    runs = []
    if not base.exists():
        return runs

    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        summary_path = entry / "summary.json"
        if not summary_path.exists():
            runs.append({"dir": entry, "malformed": True})
            continue
        try:
            data = json.loads(summary_path.read_text())
            runs.append({"dir": entry, "malformed": False, "data": data})
        except Exception:
            runs.append({"dir": entry, "malformed": True})

    return runs


def render_table(runs):
    header = f"{'RUN':<40} {'HC_RC':<7} {'SANITIZER':<10} {'PRIMARY_ERR':<12} {'FIRST LOCATION'}"
    print(header)
    print("-" * len(header))

    for r in runs:
        name = r["dir"].name
        if r["malformed"]:
            print(f"{name:<40} {'?':<7} {'<malformed>':<10} {'?':<12}")
            continue

        d = r["data"]
        hc_rc = d["run"].get("hashcat_rc_signed")
        san = d["sanitizer"]
        verdict = "PASS" if san["primary_errors"] == 0 else "FAIL"
        first = next((f for f in d["errors"] if f.get("relevance") == "primary"), None)
        frame = first.get("first_source_frame") if first else None
        loc = f"{frame['file']}:{frame['line']}" if frame else ""

        print(f"{name:<40} {str(hc_rc):<7} {verdict:<10} {san['primary_errors']:<12} {loc}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--test", default=None)
    p.add_argument("--failed", action="store_true")
    p.add_argument("--latest", type=int, default=None)
    p.add_argument("--dir", default=None)
    ns = p.parse_args(argv)

    base = Path(ns.dir) if ns.dir else DEFAULT_RESULTS_DIR
    runs = load_runs(base)

    if ns.test:
        runs = [r for r in runs if ns.test in r["dir"].name]

    if ns.failed:
        def is_failed(r):
            if r["malformed"]:
                return True
            san = r["data"]["sanitizer"]
            return san["primary_errors"] > 0 or not san["parse_ok"]
        runs = [r for r in runs if is_failed(r)]

    if ns.latest:
        runs = runs[-ns.latest:]

    if not runs:
        print("No runs found.")
        return 0

    render_table(runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
