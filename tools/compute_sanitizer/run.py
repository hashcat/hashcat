#!/usr/bin/env python3
"""CLI for running hashcat under NVIDIA Compute Sanitizer with automatic
triage down to a hashcat/OpenCL source location.

Subcommands:
  build     make clean && make DEBUG=1, produce ./hashcat-sanitizer
  check     report presence of compute-sanitizer / nvcc / a CUDA device
  exec      run one hashcat command under compute-sanitizer
  selftest  run the modules/ ground-truth fixtures and check known-good output

See README.md for the full design rationale.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import triage

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_RESULTS_DIR = SCRIPT_DIR / "results"
MODULES_DIR = SCRIPT_DIR / "modules"

VALID_TOOLS = ("memcheck", "racecheck", "synccheck", "initcheck")


def find_compute_sanitizer():
    for candidate in ("compute-sanitizer",):
        p = shutil.which(candidate)
        if p:
            return p
    # not on PATH by default in every CUDA install layout -- check common locations
    for base in sorted(Path("/usr/local").glob("cuda*")):
        cand = base / "bin" / "compute-sanitizer"
        if cand.exists():
            return str(cand)
    return None


def sanity_check_binary(binary):
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    ok = (proc.returncode == 0) and bool(proc.stdout.strip())
    return ok, proc.stdout + proc.stderr


def has_debug_info(binary):
    try:
        out = subprocess.run(["readelf", "-S", binary], capture_output=True, text=True).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return (".debug_info" in out) and (".debug_line" in out)


def find_cuda_device(binary):
    try:
        proc = subprocess.run([binary, "-I"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return None, str(e)

    out = proc.stdout
    if "CUDA Info:" not in out:
        return None, "no 'CUDA Info:' section in -I output"

    cuda_section = out.split("CUDA Info:", 1)[1].split("OpenCL Info:", 1)[0]

    if "Backend Device ID" not in cuda_section:
        return None, "no CUDA backend device listed"

    name = None
    for line in cuda_section.splitlines():
        line = line.strip()
        if line.startswith("Name"):
            name = line.split(":", 1)[1].strip()
            break

    return {"name": name}, None


def make_results_dir(base, test_name):
    base.mkdir(parents=True, exist_ok=True)
    for _ in range(20):
        ts = time.strftime("%Y%m%d-%H%M%S")
        candidate = base / f"{ts}-{test_name}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate, ts
        except FileExistsError:
            time.sleep(0.05)
    candidate = base / f"{ts}-{test_name}-{os.getpid()}"
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate, ts


def write_environment_file(path, binary, debug_ok, cuda_device):
    lines = []
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True).stdout.strip())
        lines.append(f"git_commit: {commit}")
        lines.append(f"git_dirty: {dirty}")
    except Exception:
        pass

    cs = find_compute_sanitizer()
    if cs:
        ver = subprocess.run([cs, "--version"], capture_output=True, text=True).stdout.strip()
        lines.append(f"compute_sanitizer: {ver}")

    nvcc = shutil.which("nvcc") or "/usr/local/cuda/bin/nvcc"
    if os.path.exists(nvcc):
        ver = subprocess.run([nvcc, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
        lines.append(f"nvcc: {ver}")

    lines.append(f"hashcat_binary: {binary}")
    lines.append(f"debug_info_detected: {debug_ok}")
    if cuda_device:
        lines.append(f"cuda_device: {json.dumps(cuda_device)}")

    path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def cmd_build(_ns):
    print("Building hashcat with DEBUG=1 (adds --generate-line-info to CUDA/NVRTC kernels, "
          "real .cl source names for Compute Sanitizer's backtrace)...")

    r = subprocess.run(["make", "clean"], cwd=REPO_ROOT)
    if r.returncode != 0:
        print("ERROR: make clean failed", file=sys.stderr)
        return 2

    nproc = os.cpu_count() or 1
    r = subprocess.run(["make", "DEBUG=1", f"-j{nproc}"], cwd=REPO_ROOT)
    if r.returncode != 0:
        print("ERROR: make DEBUG=1 failed", file=sys.stderr)
        return 2

    src = REPO_ROOT / "hashcat"
    dst = REPO_ROOT / "hashcat-sanitizer"
    shutil.copy(str(src), str(dst))
    os.chmod(str(dst), 0o755)

    ok, output = sanity_check_binary(str(dst))
    if not ok:
        print("ERROR: ./hashcat-sanitizer does not run cleanly after build:", file=sys.stderr)
        print(output, file=sys.stderr)
        return 2

    debug_ok = has_debug_info(str(dst))
    print(f"Built ./hashcat-sanitizer -- debug info: {'OK' if debug_ok else 'WARNING: missing'}")
    print("NOTE: ./hashcat and every modules/*.so are also now DEBUG=1 builds "
          "(one obj/ tree, unavoidable). Restore the release build afterward with:")
    print("  make clean && make -j$(nproc)")
    return 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def cmd_check(ns):
    cs = find_compute_sanitizer()
    print(f"compute-sanitizer:   {'found (' + cs + ')' if cs else 'NOT FOUND'}")

    nvcc = shutil.which("nvcc")
    if not nvcc:
        for base in sorted(Path("/usr/local").glob("cuda*")):
            cand = base / "bin" / "nvcc"
            if cand.exists():
                nvcc = str(cand)
                break
    print(f"nvcc:                {'found (' + nvcc + ')' if nvcc else 'NOT FOUND'}")

    binary = ns.binary or str(REPO_ROOT / "hashcat-sanitizer")
    debug_ok = os.path.exists(binary) and has_debug_info(binary)
    print(f"hashcat debug info:  {'found (' + binary + ')' if debug_ok else 'NOT FOUND'}")

    if os.path.exists(binary):
        device, err = find_cuda_device(binary)
        print(f"CUDA device:         {'found (' + device['name'] + ')' if device else 'NOT FOUND'}" + (f"  ({err})" if err else ""))
    else:
        print("CUDA device:         (skipped, binary not found)")

    return 0


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------

def cmd_exec(ns, sanitizer_passthrough, hc_cmd):
    if not hc_cmd:
        print("ERROR: no hashcat command given after --", file=sys.stderr)
        return 2

    import re
    if not re.match(r"^[A-Za-z0-9_-]+$", ns.test_name):
        print(f"ERROR: test-name must match [A-Za-z0-9_-]+, got: {ns.test_name!r}", file=sys.stderr)
        return 2

    cs_bin = find_compute_sanitizer()
    if cs_bin is None:
        print("ERROR: compute-sanitizer not found on PATH or under /usr/local/cuda*/bin", file=sys.stderr)
        return 2

    if ns.tool not in VALID_TOOLS:
        print(f"ERROR: --tool must be one of {VALID_TOOLS}", file=sys.stderr)
        return 2

    hc_bin = hc_cmd[0]
    hc_bin_resolved = hc_bin if os.sep in hc_bin else shutil.which(hc_bin)
    if not hc_bin_resolved or not os.path.exists(hc_bin_resolved):
        print(f"ERROR: hashcat binary not found: {hc_bin}", file=sys.stderr)
        return 2

    ok, output = sanity_check_binary(hc_bin_resolved)
    if not ok:
        print(f"ERROR: build sanity check failed for {hc_bin_resolved} -- it does not run cleanly.", file=sys.stderr)
        if output:
            print(output, file=sys.stderr)
        return 2

    debug_ok = has_debug_info(hc_bin_resolved)
    if not debug_ok:
        print(f"WARNING: {hc_bin_resolved} was not built with DEBUG=1 -- Compute Sanitizer "
              f"will still catch faults but won't resolve source:line (no --generate-line-info).", file=sys.stderr)
        print("For source-level output run: tools/compute_sanitizer/run.py build", file=sys.stderr)

    device, err = find_cuda_device(hc_bin_resolved)
    if device is None:
        print("ERROR: --compute-sanitizer requested, but no CUDA device was found.", file=sys.stderr)
        print("Check:", file=sys.stderr)
        print("  nvidia-smi", file=sys.stderr)
        print(f"  {hc_bin_resolved} -I", file=sys.stderr)
        if err:
            print(f"  ({err})", file=sys.stderr)
        return 2

    has_device_select = any(a in ("-d", "--backend-devices", "-D", "--opencl-device-types") for a in hc_cmd)
    if has_device_select:
        print("WARNING: -d/-D already present in the given command -- left as-is, but "
              "--compute-sanitizer normally forces CUDA-only via --backend-ignore-*.", file=sys.stderr)

    ignore_flags = ["--backend-ignore-opencl", "--backend-ignore-hip"]
    if sys.platform == "darwin":
        ignore_flags.append("--backend-ignore-metal")
    hc_cmd = hc_cmd + ignore_flags

    if ns.sweep:
        if not ns.results_dir:
            print("ERROR: --sweep requires --results-dir", file=sys.stderr)
            return 2
        base = Path(ns.results_dir)
    else:
        base = Path(ns.results_dir) if ns.results_dir else DEFAULT_RESULTS_DIR
    base.mkdir(parents=True, exist_ok=True)
    run_dir, ts = make_results_dir(base, ns.test_name)

    (run_dir / "command.txt").write_text("\n".join(hc_cmd) + "\n")
    write_environment_file(run_dir / "environment.txt", hc_bin_resolved, debug_ok, device)

    log_path = run_dir / "sanitizer.log"

    cs_cmd = [
        cs_bin,
        "--tool", ns.tool,
        "--check-exit-code", "no",
        "--leak-check", ns.leak_check,
        "--padding", str(ns.padding),
        "--show-backtrace", "device",
        "--print-limit", "20",
        f"--log-file={log_path}",
    ]
    # Never --error-exitcode: hashcat's own exit code must stay authoritative,
    # tracked completely separately from the sanitizer verdict (see README).
    cs_cmd += sanitizer_passthrough
    cs_cmd += ["--"] + hc_cmd

    try:
        proc = subprocess.run(cs_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"ERROR: failed to invoke compute-sanitizer: {e}", file=sys.stderr)
        return 2

    (run_dir / "stdout.txt").write_text(proc.stdout)
    (run_dir / "stderr.txt").write_text(proc.stderr)

    if ns.sweep:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)

    rc = proc.returncode
    hashcat_rc_raw = (128 - rc) if rc < 0 else rc

    summary = triage.analyze(
        str(log_path), str(REPO_ROOT), ns.tool, test_name=ns.test_name, timestamp=ts,
        command=hc_cmd, hashcat_rc_raw=hashcat_rc_raw, cuda_device_name=device.get("name"),
    )
    text = triage.write_summary(run_dir, summary, str(log_path), case_label=ns.test_name)

    if ns.sweep:
        triage.append_sweep_finding(base, run_dir.name, summary)
        return hashcat_rc_raw

    print(text)
    return summary["run"].get("wrapper_rc", 2)


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def _run_make_modules():
    r = subprocess.run(["make"], cwd=MODULES_DIR)
    return r.returncode == 0


def _run_selftest_case(name, binary_path, cs_bin, tool, results_dir):
    run_dir, ts = make_results_dir(results_dir, name)
    log_path = run_dir / "sanitizer.log"

    cs_cmd = [
        cs_bin, "--tool", tool, "--check-exit-code", "no", "--leak-check", "no",
        "--padding", "128",
        "--show-backtrace", "device", "--print-limit", "20", f"--log-file={log_path}",
        "--", str(binary_path),
    ]

    try:
        proc = subprocess.run(cs_cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return False, None, None, str(e)

    (run_dir / "stdout.txt").write_text(proc.stdout)
    (run_dir / "stderr.txt").write_text(proc.stderr)

    summary = triage.analyze(str(log_path), str(REPO_ROOT), tool, test_name=name, timestamp=ts,
                              command=[str(binary_path)], hashcat_rc_raw=proc.returncode)
    triage.write_summary(run_dir, summary, str(log_path), case_label=name)

    if not summary["sanitizer"]["parse_ok"]:
        return False, None, None, "log parse failed"

    primary = [f for f in summary["errors"] if f.get("relevance") == "primary"]
    if primary:
        f0 = primary[0]
        frame = f0.get("first_source_frame")
        loc = f"{frame['file']}:{frame['line']}" if frame else "unresolved"
        return True, f0["kind"], loc, None

    return True, None, None, "no primary errors found"


def cmd_selftest(args):
    expected_path = MODULES_DIR / "expected.json"
    if not expected_path.exists():
        print(f"ERROR: {expected_path} not found", file=sys.stderr)
        return 2
    expected = json.loads(expected_path.read_text())

    cs_bin = find_compute_sanitizer()
    if cs_bin is None:
        print("ERROR: compute-sanitizer not found", file=sys.stderr)
        return 2

    if not _run_make_modules():
        print("ERROR: failed to build tools/compute_sanitizer/modules/ fixtures", file=sys.stderr)
        return 2

    results_dir = DEFAULT_RESULTS_DIR / "selftest"
    if results_dir.exists():
        shutil.rmtree(results_dir)
    results_dir.mkdir(parents=True)

    rows = []
    all_ok = True
    for name, exp in expected.items():
        binary_path = MODULES_DIR / name
        tool = exp.get("tool", "memcheck")

        ok, actual_kind, actual_loc, detail = _run_selftest_case(name, binary_path, cs_bin, tool, results_dir)
        want_kind = exp.get("kind")
        passed = ok and actual_kind == want_kind
        all_ok = all_ok and passed
        rows.append((name, "PASS" if passed else "FAIL",
                     f"expected {want_kind}, got {actual_kind}" + (f" ({actual_loc})" if actual_loc else "") +
                     (f" -- {detail}" if detail and not passed else "")))

    for name, status, detail in rows:
        print(f"{name:<20} {status:<5} {detail}")

    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def split_exec_args(argv):
    if "--" not in argv:
        return argv, None
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1:]


def build_exec_parser():
    p = argparse.ArgumentParser(prog="run.py exec", add_help=True,
                                 description="Run one hashcat command under Compute Sanitizer with triage.")
    p.add_argument("test_name")
    p.add_argument("--tool", default="memcheck", choices=VALID_TOOLS,
                    help="Compute Sanitizer tool to use (default: memcheck)")
    p.add_argument("--leak-check", default="no", choices=("no", "full"))
    p.add_argument("--padding", type=int, default=128,
                    help="Compute Sanitizer --padding: bytes of tracked redzone appended after every "
                         "device allocation, so a read/write that overshoots one buffer but happens to "
                         "land inside a neighboring allocation is still flagged instead of going silent "
                         "(default: 128; 0 disables it, matching compute-sanitizer's own default)")
    p.add_argument("--sweep", action="store_true",
                    help="non-interactive mode for test.sh/test_edge.sh: hashcat's stdout/stderr/exit-code "
                         "pass through untouched; requires --results-dir")
    p.add_argument("--results-dir", default=None)
    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    subcmd, rest = argv[0], argv[1:]

    if subcmd == "build":
        return cmd_build(argparse.Namespace())

    if subcmd == "check":
        p = argparse.ArgumentParser(prog="run.py check")
        p.add_argument("--binary", default=None)
        return cmd_check(p.parse_args(rest))

    if subcmd == "exec":
        pre_args, hc_cmd = split_exec_args(rest)
        if hc_cmd is None:
            print("ERROR: exec requires a hashcat command after --", file=sys.stderr)
            return 2
        parser = build_exec_parser()
        ns, unknown = parser.parse_known_args(pre_args)
        return cmd_exec(ns, unknown, hc_cmd)

    if subcmd == "selftest":
        p = argparse.ArgumentParser(prog="run.py selftest")
        return cmd_selftest(p.parse_args(rest))

    print(f"ERROR: unknown subcommand {subcmd!r}", file=sys.stderr)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
