#!/usr/bin/env python3
"""Parses NVIDIA Compute Sanitizer plain-text logs, classifies findings, and
produces the JSON/terminal summary used by run.py and report.py.

Log format (every line prefixed "========= ", confirmed against a real
captured sample built from a deliberate out-of-bounds __global__ write,
compiled with `nvcc -lineinfo` and run under
`compute-sanitizer --tool memcheck --show-backtrace device`):

    ========= COMPUTE-SANITIZER
    ========= Invalid __global__ write of size 4 bytes
    =========     at oob_write_kernel(int *, int)+0x70 in oob_test.cu:7
    =========     by thread (31,0,0) in block (0,0,0)
    =========     Access at 0x503600080 is out of bounds
    =========     and is 1 bytes after the nearest allocation at 0x503600000 of size 128 bytes
    =========
    ========= Program hit cudaErrorLaunchFailure (error 719) due to "unspecified
    launch failure" on CUDA API call to cudaDeviceSynchronize.
    =========
    ========= ERROR SUMMARY: 3 errors

A real memory-safety fault poisons the CUDA context: every subsequent CUDA
API call in the same process reports its own "Program hit cudaError..."
block. Those are real Compute Sanitizer errors but are *consequences* of the
first fault, not independent findings, classified separately as
"secondary" so they don't drown out the one thing a human needs to look at.
"""

import json
import os
import re
import subprocess

SCHEMA_VERSION = 1

_KIND_PATTERNS = [
    (re.compile(r"^Invalid __global__ read of size \d+ bytes?"), "InvalidGlobalRead"),
    (re.compile(r"^Invalid __global__ write of size \d+ bytes?"), "InvalidGlobalWrite"),
    (re.compile(r"^Invalid __shared__ read of size \d+ bytes?"), "InvalidSharedRead"),
    (re.compile(r"^Invalid __shared__ write of size \d+ bytes?"), "InvalidSharedWrite"),
    (re.compile(r"^Invalid __local__ read of size \d+ bytes?"), "InvalidLocalRead"),
    (re.compile(r"^Invalid __local__ write of size \d+ bytes?"), "InvalidLocalWrite"),
    (re.compile(r"^Invalid __constant__ read of size \d+ bytes?"), "InvalidConstantRead"),
    (re.compile(r"^Misaligned"), "MisalignedAccess"),
    (re.compile(r"[Oo]ut.of.bounds"), "OutOfBoundsAccess"),
    (re.compile(r"[Uu]ninitializ"), "UninitializedDeviceMemory"),
    (re.compile(r"^Race reported|[Pp]otential race|[Rr]ace condition"), "RaceHazard"),
    (re.compile(r"[Bb]arrier error|[Ss]ynchronization error|divergent __syncthreads"), "SyncBarrierError"),
    (re.compile(r"^Program hit .* due to|^Program hit cuda"), "CudaAPIError"),
    (re.compile(r"^Leaked"), "MemoryLeak"),
]

_FRAME_FILE_LINE_RE = re.compile(
    r"^at\s+(?P<fn>.+?)(?:\+0x[0-9a-fA-F]+)?\s+in\s+(?P<file>[^\s:][^:]*):(?P<line>\d+)\s*$"
)
_FRAME_BARE_RE = re.compile(
    r"^at\s+(?P<fn>.+?)(?:\+0x[0-9a-fA-F]+)?\s*(?:\(0x[0-9a-fA-F]+\))?\s*$"
)
_FRAME_IN_OBJ_RE = re.compile(
    r"^at\s+(?P<fn>.+?)(?:\+0x[0-9a-fA-F]+)?\s+in\s+(?P<obj>.+?)\s*$"
)
_THREAD_BLOCK_RE = re.compile(
    r"^by thread \((\d+),(\d+),(\d+)\) in block \((\d+),(\d+),(\d+)\)\s*$"
)
_ACCESS_RE = re.compile(
    r"^Access at (0x[0-9a-fA-F]+) is (out of bounds|misaligned)"
)
_ALLOC_RE = re.compile(
    r"^and is (\d+) bytes? (after|before) the nearest allocation at (0x[0-9a-fA-F]+) of size (\d+) bytes?"
)
_BARE_ADDRESS_RE = re.compile(r"^Address (0x[0-9a-fA-F]+)\s*$")
# Anchored with a trailing $ so this doesn't also swallow the follow-up
# "ERROR SUMMARY: N errors were not printed. Use --print-limit ..." line,
# which starts with the same literal but isn't the real total.
_ERROR_SUMMARY_RE = re.compile(r"^ERROR SUMMARY:\s*(\d+) errors?\s*$")
# racecheck doesn't use "ERROR SUMMARY:" at all; its own tool-specific
# footer is "RACECHECK SUMMARY: N hazards displayed (X errors, Y warnings)".
# Confirmed against a real clean run; without this, that line falls through
# to the generic "new block" branch and gets misclassified as a spurious
# "Unknown" finding on every racecheck run, clean or not.
_RACECHECK_SUMMARY_RE = re.compile(
    r"^RACECHECK SUMMARY:\s*\d+ hazards? displayed\s*\((\d+) errors?,\s*\d+ warnings?\)\s*$"
)


def infer_kind(what_text):
    for pattern, kind in _KIND_PATTERNS:
        if pattern.search(what_text):
            return kind
    return "Unknown"


def _strip_prefix(line):
    # "========= " (with or without a trailing space, and the log may use a
    # slightly different number of '=' depending on sanitizer version, so
    # match the run of '=' rather than a fixed-width literal).
    m = re.match(r"^=+\s?(.*)$", line)
    return m.group(1) if m else None


def parse_sanitizer_log(log_path):
    """Returns (findings, total_errors_reported). findings is a list of dicts:
    {kind, what, frames: [{fn, file, line}], thread, block, access, allocation}
    frames is ordered outermost-call-site-first as printed by Compute Sanitizer
    (the first frame is where the fault happened)."""

    if not os.path.exists(log_path):
        raise FileNotFoundError(log_path)

    with open(log_path, "r", errors="replace") as f:
        raw_lines = f.readlines()

    total_errors_reported = None
    blocks = []
    current = None

    for raw in raw_lines:
        line = raw.rstrip("\n")
        content = _strip_prefix(line)
        if content is None:
            continue  # not a compute-sanitizer line (e.g. hashcat's own stdout, if interleaved)

        content = content.strip()

        if content == "COMPUTE-SANITIZER":
            continue

        m = _ERROR_SUMMARY_RE.match(content)
        if m:
            total_errors_reported = int(m.group(1))
            continue

        m = _RACECHECK_SUMMARY_RE.match(content)
        if m:
            total_errors_reported = int(m.group(1))
            continue

        if content.startswith("ERROR SUMMARY:") or content.startswith("RACECHECK SUMMARY:"):
            # The "N errors were not printed. Use --print-limit ..." follow-up
            # line when --print-limit truncated output: informational, not
            # a finding of its own. Also catches any RACECHECK SUMMARY: shape
            # that doesn't match the regex above (e.g. a truncated variant).
            continue

        if content == "":
            current = None
            continue

        if (content.startswith("at ") or content.startswith("by ") or content.startswith("Access ")
                or content.startswith("and ") or content.startswith("Address ")):
            if current is None:
                # Detail line with no preceding "what": shouldn't happen given
                # the observed format, but don't crash on an unexpected log.
                current = {"kind": "Unknown", "what": "", "frames": [], "thread": None,
                           "block": None, "access": None, "allocation": None}
                blocks.append(current)
            _parse_detail_line(content, current)
            continue

        # A new block's "what" line.
        current = {
            "kind": infer_kind(content),
            "what": content,
            "frames": [],
            "thread": None,
            "block": None,
            "access": None,
            "allocation": None,
        }
        blocks.append(current)

    return blocks, total_errors_reported


def _parse_detail_line(content, current):
    m = _THREAD_BLOCK_RE.match(content)
    if m:
        tx, ty, tz, bx, by, bz = (int(x) for x in m.groups())
        current["thread"] = {"x": tx, "y": ty, "z": tz}
        current["block"] = {"x": bx, "y": by, "z": bz}
        return

    m = _ACCESS_RE.match(content)
    if m:
        current["access"] = {"address": m.group(1), "problem": m.group(2)}
        return

    m = _ALLOC_RE.match(content)
    if m:
        current["allocation"] = {
            "offset_bytes": int(m.group(1)),
            "relation": m.group(2),
            "address": m.group(3),
            "size_bytes": int(m.group(4)),
        }
        return

    m = _BARE_ADDRESS_RE.match(content)
    if m:
        # initcheck's format: just "Address 0x..." with no allocation-offset
        # detail (unlike memcheck's "Access at ... is out of bounds").
        current["access"] = {"address": m.group(1), "problem": "uninitialized"}
        return

    if content.startswith("at "):
        m = _FRAME_FILE_LINE_RE.match(content)
        if m:
            current["frames"].append({
                "fn": m.group("fn").strip(),
                "file": m.group("file").strip(),
                "line": int(m.group("line")),
                "obj": None,
            })
            return

        m = _FRAME_IN_OBJ_RE.match(content)
        if m:
            current["frames"].append({
                "fn": m.group("fn").strip(),
                "file": None,
                "line": None,
                "obj": m.group("obj").strip(),
            })
            return

        m = _FRAME_BARE_RE.match(content)
        if m:
            current["frames"].append({
                "fn": m.group("fn").strip(),
                "file": None,
                "line": None,
                "obj": None,
            })
            return

    # "and " lines that don't match _ALLOC_RE, or other unrecognized detail
    # lines: keep as a free-text note rather than silently dropping them.
    current.setdefault("notes", []).append(content)


def first_source_frame(finding):
    """First frame with a real file:line (a fixture .cu or a real hashcat
    .cl), as opposed to a bare function/offset or a shared-object frame."""
    for frame in finding["frames"]:
        if frame.get("file") and frame.get("line") is not None:
            return frame
    return None


def classify_relevance(findings):
    """Marks each finding's "relevance": a real memory/race/sync fault is
    "primary"; a CudaAPIError block is "secondary" (a consequence of an
    earlier real fault poisoning the CUDA context) unless it is the only
    finding in the run, in which case it's promoted to "primary" (pure CUDA
    API misuse with no preceding memory fault is still worth surfacing)."""

    saw_primary = False
    for finding in findings:
        if finding["kind"] != "CudaAPIError":
            finding["relevance"] = "primary"
            saw_primary = True

    for finding in findings:
        if finding["kind"] == "CudaAPIError":
            finding["relevance"] = "secondary" if saw_primary else "primary"


def _git_info(repo_root):
    def run(args):
        try:
            return subprocess.run(args, cwd=repo_root, capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            return None

    commit = run(["git", "rev-parse", "HEAD"])
    dirty = run(["git", "status", "--porcelain"])
    return {"commit": commit, "dirty": bool(dirty)}


def _tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        return out.strip().splitlines()[0] if out.strip() else None
    except Exception:
        return None


def gather_environment(repo_root, cuda_device_name=None):
    env = {}
    env["git"] = _git_info(repo_root)
    env["compute_sanitizer_version"] = _tool_version(["compute-sanitizer", "--version"])
    env["nvcc_version"] = _tool_version(["nvcc", "--version"])
    env["cuda_device_name"] = cuda_device_name
    return env


def analyze(log_path, repo_root, tool, test_name="", timestamp="", command=None,
            hashcat_rc_raw=None, cuda_device_name=None):
    try:
        findings, total_reported = parse_sanitizer_log(log_path)
        parse_ok = True
        parse_error = None
    except Exception as e:
        findings, total_reported = [], None
        parse_ok = False
        parse_error = str(e)

    classify_relevance(findings)

    for finding in findings:
        frame = first_source_frame(finding)
        finding["first_source_frame"] = frame

    primary = [f for f in findings if f.get("relevance") == "primary"]
    secondary = [f for f in findings if f.get("relevance") == "secondary"]

    hashcat_rc_signed = None
    if hashcat_rc_raw is not None:
        hashcat_rc_signed = hashcat_rc_raw - 256 if hashcat_rc_raw > 127 else hashcat_rc_raw

    if not parse_ok:
        wrapper_rc = 2
    elif len(primary) > 0:
        wrapper_rc = 1
    else:
        wrapper_rc = 0

    result = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "test_name": test_name,
            "timestamp": timestamp,
            "command": command,
            "hashcat_rc_raw": hashcat_rc_raw,
            "hashcat_rc_signed": hashcat_rc_signed,
            "wrapper_rc": wrapper_rc,
        },
        "environment": gather_environment(repo_root, cuda_device_name),
        "sanitizer": {
            "tool": tool,
            "parse_ok": parse_ok,
            "parse_error": parse_error,
            "total_errors_reported": total_reported,
            "total_errors": len(findings),
            "primary_errors": len(primary),
            "secondary_errors": len(secondary),
        },
        "errors": findings,
    }

    return result


def render_terminal(summary, log_path, case_label=None):
    lines = []

    label = case_label or summary["run"].get("test_name") or ""
    if label:
        lines.append(f"[ {label} ]")
        lines.append("")

    hc_rc = summary["run"].get("hashcat_rc_signed")
    lines.append(f"Hashcat: {'PASS' if hc_rc == 0 else f'rc={hc_rc}'}")

    san = summary["sanitizer"]
    if not san["parse_ok"]:
        lines.append(f"Compute Sanitizer: FAIL (log parse error: {san['parse_error']})")
        return "\n".join(lines)

    verdict = "PASS" if san["primary_errors"] == 0 else "FAIL"
    lines.append(f"Compute Sanitizer ({san['tool']}): {verdict}")
    lines.append("")

    for finding in summary["errors"]:
        if finding.get("relevance") != "primary":
            continue

        lines.append(finding["kind"])

        frame = finding.get("first_source_frame")
        if frame:
            lines.append(f"  {frame['file']}:{frame['line']}")
            lines.append(f"  {frame['fn']}()")
        elif finding["frames"]:
            f0 = finding["frames"][0]
            where = f0.get("obj") or "unresolved"
            lines.append(f"  {f0['fn']}() (in {where}, no line info)")

        lines.append("")

        if finding.get("thread"):
            t, b = finding["thread"], finding["block"]
            lines.append(f"  thread ({t['x']},{t['y']},{t['z']})")
            lines.append(f"  block  ({b['x']},{b['y']},{b['z']})")
            lines.append("")

    if san["secondary_errors"] > 0:
        lines.append(f"({san['secondary_errors']} secondary CUDA API error(s) omitted, "
                      f"consequences of the fault above poisoning the CUDA context, not independent findings)")
        lines.append("")

    lines.append("Full report:")
    lines.append(f"  {log_path}")

    return "\n".join(lines)


def write_summary(run_dir, summary, log_path, case_label=None):
    text = render_terminal(summary, log_path, case_label=case_label)

    (run_dir / "summary.txt").write_text(text + "\n")

    tmp_path = run_dir / "summary.json.tmp"
    tmp_path.write_text(json.dumps(summary, indent=2))
    os.replace(str(tmp_path), str(run_dir / "summary.json"))

    return text


def append_sweep_finding(sweep_dir, run_name, summary):
    tsv_path = sweep_dir / "sweep-findings.tsv"
    is_new = not tsv_path.exists()

    san = summary["sanitizer"]
    first = next((f for f in summary["errors"] if f.get("relevance") == "primary"), None)
    frame = first.get("first_source_frame") if first else None
    location = f"{frame['file']}:{frame['line']}" if frame else ""

    with open(tsv_path, "a") as f:
        if is_new:
            f.write("run\thc_rc\ttool\tprimary_errors\tsecondary_errors\tfirst_kind\tfirst_location\n")
        f.write(f"{run_name}\t{summary['run'].get('hashcat_rc_signed')}\t{san['tool']}\t"
                f"{san['primary_errors']}\t{san['secondary_errors']}\t"
                f"{first['kind'] if first else ''}\t{location}\n")
