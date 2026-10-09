#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# A python manager for the modes that have a python oracle. It asks tools/test_module_runner.py for
# test vectors, runs ./hashcat on them and reports the OK/Error/Skip summary line the old
# tools/test.sh printed, so a run reads line for line the way that suite's did. ATTACKS lists the
# attack modes it runs, and it runs every one the old suite did.

import argparse
import atexit
import base64
import fcntl
import glob
import importlib.util
import json
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

TDIR   = os.path.dirname(os.path.abspath(__file__))
ROOT   = os.path.dirname(TDIR)
RUNNER = os.path.join(TDIR, "test_module_runner.py")
BIN    = os.path.join(ROOT, "hashcat")

# Per-process isolation of hashcat's mutable per-run state, so any number of test.py processes (and
# -j workers) run without stepping on each other. Every hashcat call gets these:
#   --cache-path <private dir>  a kernel cache of this process's own, which also isolates the
#                               rebuildable dictstat cache; the cache is not shared, but because
#                               each mode runs in one process its kernels are still built only once.
#   --session <pid>            a unique session name so no <session> file collides.
#   --restore-disable          no <session>.restore file at all; a test run never resumes.
# Unlike test.sh/test_edge, test.py never runs "rm -rf cache/kernels", so nothing deletes a cache
# another process is using. ISOLATION is filled once by setup_isolation() and appended to every opts.
ISOLATION = []


def setup_isolation():
  global ISOLATION

  if ISOLATION:
    return

  cache_dir = tempfile.mkdtemp(prefix="test_py_cache_")
  atexit.register(shutil.rmtree, cache_dir, ignore_errors=True)

  ISOLATION = ["--cache-path", cache_dir, "--session", "testpy_%d" % os.getpid(), "--restore-disable"]


# The most recent hashcat argv, set by run_hashcat and read by the logfull writer. A worker is one
# process running its modes in sequence, so the last run is the one classify() is scoring.
LAST_CMD = None

# test.sh kept a test_<ts>/ folder per run. OUTDIR is its path or None, LOGFULL the open logfull.txt
# handle. OWN_OUTDIR is True only in the process that made the folder, so a -j child does not
# regenerate the parent's derived files. PROGRESS is the running tally the interrupt handler prints.
OUTDIR     = None
OWN_OUTDIR = False
LOGFULL    = None
PROGRESS   = {}

# The count of results in the serial run that mean a test which should have cracked did not, or hit a
# hard error. The -j and edge paths compute their own return code; the plain path had none and fell
# off the end of main() as 0 even when every case faulted, so it is tracked here and main() exits on
# it. A Warning (a --runtime timeout) and a Skip are not failures, so they are left out.
ERRORS        = 0
FAIL_VERDICTS = ("Fault", "Error", "Compare Error")

# The CPU's backend device number, cached: -1 before it is looked up, then the number or None. It
# pins the virtual host for a bridged mode (see bridge_opts).
CPU_BACKEND_ID = -1

# A -j worker that skips on 252 (memory hit limit) only because its share of the card was too small
# exits with MEMSKIP_RC, so run_parallel re-runs that mode with the caps removed and the coverage
# survives. A 252 with no cap in the environment is a genuine skip and does not set this.
CAPPED_MEM_SKIP = False
MEMSKIP_RC = 90

AUTO_LOGDIR = "\0auto"     # --logdir with no argument: pick test_<ts>/

# test.sh's status() reason strings, keyed by hashcat's exit code. The 246,248-253 and 30 codes are
# runtime skips; 1 is a clean exhaust, 4 a timeout, 10 a crack whose plains were not in the output.
REASON = {
  246: "autotune failure",
  248: "skipped by runtime (mixed backend errors detected)",
  249: "skipped by runtime (Invalid module_extra_buffer_size)",
  250: "skipped by runtime (Too many compute units to keep minimum kernel accel limit)",
  251: "skipped by runtime (main kernel build error)",
  252: "skipped by runtime (memory hit limit)",
  253: "skipped by runtime (module_unstable_warning)",
  30:  "luks test files are missing",
  1:   "password not found",
  4:   "timeout reached",
  10:  "hash:plains not matched in output",
}


def reason_for(ret):
  # The English reason for a non-zero hashcat result, for logfull.txt. A code outside the known set is
  # an error rather than a result: a negative return is a process killed by a signal (subprocess
  # reports -signum), and hashcat's own error codes wrap to 255 (255 is -1) and above.
  if ret in REASON:
    return REASON[ret]

  if ret < 0:
    return "hashcat crashed, killed by signal %d" % (-ret)

  return "hashcat error (return code %d)" % ret


def _cmdline(cmd):
  return " ".join(shlex.quote(str(a)) for a in cmd)


def logfull_append(text):
  # test.sh's logfull.txt was one serial stream. A -j run has several workers writing the one shared
  # file, so each block is appended under an exclusive lock and stays whole. Blocks land in completion
  # order under -j, in run order for a serial run.
  if LOGFULL is None:
    return

  if not text.endswith("\n"):
    text += "\n"

  try:
    fcntl.flock(LOGFULL, fcntl.LOCK_EX)
    LOGFULL.write(text)
    LOGFULL.flush()
  except Exception:
    pass
  finally:
    try:
      fcntl.flock(LOGFULL, fcntl.LOCK_UN)
    except Exception:
      pass


def log_output(cmd, output):
  # test.sh wrote every run's whole hashcat output to logfull.txt under a header naming the run, so the
  # folder held the entire transcript. Match it: the cmdline as the header, then the output.
  text = output.decode("utf-8", "replace") if isinstance(output, bytes) else output
  logfull_append("> cmdline : %s\n%s" % (_cmdline(cmd), text.rstrip("\n")))


def log_result(ret):
  # test.sh's status() added a one-line reason after the output for a non-OK result. Keep it, so the
  # failures can be grepped out of logfull.txt into summary.txt.
  if ret == 0 or LAST_CMD is None:
    return

  logfull_append("%s, cmdline : %s" % (reason_for(ret), _cmdline(LAST_CMD)))


def record(v):
  PROGRESS[v] = PROGRESS.get(v, 0) + 1


def note_verdict(v):
  # Called wherever a result verdict is decided, so the serial path can exit non-zero on a real
  # failure the way run_parallel and run_edge already return 1.
  if v in FAIL_VERDICTS:
    global ERRORS
    ERRORS += 1


def print_total():
  parts = ", ".join("%s=%d" % (k, PROGRESS[k]) for k in sorted(PROGRESS) if PROGRESS[k])
  print("[ test.py ] > totals so far: %s" % (parts or "nothing run yet"))


def host_avail_mib():
  try:
    with open("/proc/meminfo") as fh:
      for line in fh:
        if line.startswith("MemAvailable:"):
          return int(line.split()[1]) // 1024
  except Exception:
    pass

  return None


def backend_devices():
  # Run "hashcat -I --machine-readable" and hand its JSON to parse_backend_devices. Returns [] when -I
  # cannot be read; parse failures are handled by the parser.
  try:
    proc = subprocess.run([BIN, "-I", "--machine-readable"] + ISOLATION, cwd=ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
  except Exception:
    return []

  return parse_backend_devices(proc.stdout.decode("utf-8", "replace"))


def parse_backend_devices(text):
  # Parse "hashcat -I --machine-readable" output into a list of {id, type, free, backend, alias} per
  # backend device. The JSON hands back DeviceID, MemoryFree and, for a same-card pair, Alias as real
  # fields, so there is nothing to scrape. Only the Metal and OpenCL device objects carry a Type; the
  # CUDA and HIP objects omit it. CUDA, HIP and Metal only ever enumerate GPUs, so a device under one of
  # those sections is taken as a GPU, which is also the only way to type a native CUDA or HIP device,
  # since hashcat gives it no Type at all. -I lists every device regardless of -D, so callers filter by
  # type themselves. Returns [] when the JSON cannot be parsed. Split from backend_devices so it can be
  # unit tested on fixed -I fixtures without a GPU.
  try:
    info = json.loads(text)
  except Exception:
    return []

  gpu_only = {"CUDA", "HIP", "METAL"}
  out      = []

  def add(backend, dev):
    # DeviceID and Alias print zero-padded ("01"); MemoryFree is "<n> MB". Skip a device whose id does
    # not parse rather than let one bad object drop the whole list.
    try:
      did = int(dev["DeviceID"])
    except (KeyError, TypeError, ValueError):
      return

    typ = dev.get("Type")
    typ = typ.upper() if typ else ("GPU" if backend in gpu_only else None)

    free = None
    mem = dev.get("MemoryFree")
    if mem:
      head = str(mem).split()[0]
      if head.isdigit():
        free = int(head)

    alias = dev.get("Alias")
    try:
      alias = int(alias) if alias is not None else None
    except (TypeError, ValueError):
      alias = None

    out.append({"id": did, "type": typ, "free": free, "backend": backend, "alias": alias})

  # CUDA, HIP and Metal list their devices directly under the section; OpenCL groups them by platform.
  for section, body in info.items():
    if not isinstance(body, dict):
      continue

    backend = section[:-4].upper() if section.endswith("Info") else section.upper()

    for dev in body.get("BackendDevices", []):
      add(backend, dev)

    for plat in body.get("Platforms", []):
      if isinstance(plat, dict):
        for dev in plat.get("BackendDevices", []):
          add(backend, dev)

  return out


def wanted_types(device):
  # The -I Type strings a -D device list selects. -D is a device-type list: 1 CPU, 2 GPU, 3 FPGA. An
  # empty set means no recognizable type, which the callers read as "match every device".
  type_of = {"1": "CPU", "2": "GPU", "3": "FPGA"}

  return {type_of[d] for d in re.split(r"[ ,]+", device.strip()) if d in type_of}


def min_device_free_mib(device, devices=None):
  # The smallest free-memory reading among the devices this run will use. A CPU device's reading must
  # not set a GPU run's share, so keep only devices whose Type matches -D. One HASHCAT_DEVICE_MEM_LIMIT
  # serves every device, so the smallest matching one is the safe share. Returns None when nothing
  # matches, so the caller leaves the cap unset. devices lets a test pass a parsed list in place of the
  # live -I query.
  want  = wanted_types(device)
  devs  = backend_devices() if devices is None else devices
  frees = [d["free"] for d in devs
           if d["free"] is not None and (not want or d["type"] in want)]

  return min(frees) if frees else None


def dedup_alias_devices(devices):
  # hashcat lists a card once per backend that sees it: a CUDA or HIP card also shows up as an OpenCL
  # device whose Alias field back-references its native twin, and hashcat itself skips the OpenCL twin
  # and runs the native one. Mirror that so the depth split pins to the device hashcat actually uses and
  # opens one slot per physical card, not one per backend view of it. Keep the native (CUDA, HIP or
  # Metal) side of an alias pair, drop the OpenCL alias, and keep every unaliased device.
  by_id = {d["id"]: d for d in devices}
  skip  = set()

  for d in devices:
    other = by_id.get(d["alias"])
    if other is not None and d["backend"] == "OPENCL" and other["backend"] != "OPENCL":
      skip.add(d["id"])

  return [d for d in devices if d["id"] not in skip]


def backend_ids_for(device, devices=None):
  # The backend device numbers whose Type matches the -D type list, one id per physical card (alias
  # twins removed, see dedup_alias_devices), for the depth -j split. devices lets a test pass a parsed
  # list in place of the live -I query.
  want = wanted_types(device)
  devs = backend_devices() if devices is None else devices

  return [d["id"] for d in dedup_alias_devices(devs)
          if not want or d["type"] in want]


def export_worker_mem_shares(args):
  # Under -j each worker reads the whole card and host as free and sizes itself to it,
  # so N of them together ask for N times what exists and the later ones die on out of memory. Hand
  # each worker its own share through HASHCAT_DEVICE_MEM_LIMIT and HASHCAT_HOST_MEM_LIMIT, in MiB; the
  # child inherits the two from this process. A hashcat that predates them ignores the env, so on an
  # older build this is a no-op rather than a break.
  if args.jobs <= 1:
    return

  dev = min_device_free_mib(args.device)
  if dev:
    os.environ["HASHCAT_DEVICE_MEM_LIMIT"] = str(max(1, dev // args.jobs))

  host = host_avail_mib()
  if host:
    os.environ["HASHCAT_HOST_MEM_LIMIT"] = str(max(1, host // args.jobs))


def setup_outdir(args):
  # test.sh named every run's output folder test_<ts>/ and kept its logfull.txt there. test.py does
  # the same by default: the folder is made on every run, test.py choosing the name, unless --logdir
  # names one. A -j child inherits the parent's folder through the environment rather than making its
  # own, so one -j run has one folder, not one per worker.
  global OUTDIR, LOGFULL, OWN_OUTDIR

  inherited = os.environ.get("TESTPY_OUTDIR")

  if inherited and os.path.isdir(inherited):
    # A -j child appends its own runs to the shared logfull.txt; the parent, which owns the folder,
    # writes the derived test_report.log and summary.txt once the run ends.
    OUTDIR  = inherited
    LOGFULL = open(os.path.join(inherited, "logfull.txt"), "a")
    return

  if args.logdir and args.logdir != AUTO_LOGDIR:
    path = args.logdir
  else:
    path = "test_%d" % int(time.time())

  os.makedirs(path, exist_ok=True)
  OUTDIR     = path
  OWN_OUTDIR = True
  LOGFULL    = open(os.path.join(path, "logfull.txt"), "a")
  os.environ["TESTPY_OUTDIR"] = os.path.abspath(path)

  # Say where only when the user named the folder. The default is silent, as test.sh was, so a run's
  # console output is the same bytes with or without the folder.
  if args.logdir:
    print("[ test.py ] > logging to %s/ (logfull.txt, test_report.log, summary.txt)" % path)


def finalize_outputs(note):
  # test.sh left three files in the folder: logfull.txt (the whole transcript, written as the run
  # goes), test_report.log (that transcript with hashcat's carriage-return progress redraws
  # collapsed), and, added here, summary.txt (the failures plus the run tally). The folder owner
  # writes the two derived files once, at exit or on Ctrl-C, from the logfull.txt every process
  # appended to.
  if not OWN_OUTDIR or OUTDIR is None:
    return

  try:
    if LOGFULL is not None:
      LOGFULL.flush()
  except Exception:
    pass

  try:
    with open(os.path.join(OUTDIR, "logfull.txt"), "r", errors="replace") as src:
      lines = src.readlines()
  except Exception:
    lines = []

  # test_report.log: keep only the segment after the last carriage return on each line, the final
  # state hashcat's in-place progress line would have shown.
  try:
    with open(os.path.join(OUTDIR, "test_report.log"), "w") as rep:
      for line in lines:
        rep.write(line.rsplit("\r", 1)[-1])
  except Exception:
    pass

  # summary.txt: every non-OK run logs a reason line ending ", cmdline : ...", so those are the
  # errors and skips; then the tally. Nothing else.
  try:
    issues = [l for l in lines if ", cmdline : " in l]

    with open(os.path.join(OUTDIR, "summary.txt"), "w") as smy:
      smy.write("%s\n\nerrors and skips (%d):\n" % (note, len(issues)))

      for l in issues:
        smy.write(l if l.endswith("\n") else l + "\n")

      smy.write("\nresults:\n")

      for k in sorted(PROGRESS):
        smy.write("  %s = %d\n" % (k, PROGRESS[k]))
  except Exception:
    pass


def on_sigint(signum, frame):
  # Ctrl-C: write the derived files from what has been logged so far and print the running total,
  # rather than dropping the run.
  sys.stdout.flush()
  finalize_outputs("interrupted")

  print("\n[ test.py ] > interrupted")

  if OUTDIR:
    print("[ test.py ] > latest results written to %s/" % OUTDIR)

  print_total()
  os._exit(130)


SINGLE_MAX = 32     # test.sh caps a single-target run at 32 hashes
RUNTIME    = 400    # hashcat --runtime, as test.sh sets it

# A binary-hashfile mode (OPTS_TYPE_BINARY_HASHFILE) is handed a file, not a hash string, so the
# oracle prints the file base64 encoded and the manager decodes it back to a file (test.sh).
# For those, and for the two encoding exceptions, the recovered line does not carry the
# hash we started from, so the match is on ":password" alone (test.sh PASS_ONLY).

NOCHECK_ENCODING = {16800, 16801, 22000}

# Modes whose only kernel is the mask attack (mfulc 37000 ships m37000_a3-pure.cl and nothing else),
# so every other attack has no kernel to run and is left out rather than failing on a missing file.

MASK_ONLY_MODES = {37000}

# MIFARE Ultralight C 3DES key recovery: the key recovery is not unique, so hashcat may recover a
# different valid 4 byte segment than the oracle used. Its crack is scored by the hash appearing in
# the output, whatever segment was printed with it.

MFULC_MODES = {37000}

# The LUKS modes whose hashes are container paths, not the generator's own output. whole_word_vectors
# leaves their -a 4 list alone (test.sh); 10300 takes its hash from another field and is excluded
# there too.

LUKS_MODES = {29511, 29512, 29513, 29521, 29522, 29523, 29531, 29532, 29533, 29541, 29542, 29543,
              34100}

# The modes test.sh's has_multi_hash reports true for: one hash each, so no multi-hash run at all
# (test.sh). 37500 joins them because its oracle builds every hash on one fixed salt, and a slow mode
# with an esalt and no OPTS_TYPE_MULTIHASH_DESPITE_ESALT refuses more than one hash per salt. 5200
# and 9000 read the hash file as one Password Safe database, so a file of several loads only the
# first.

MULTI_ONE_HASH = {5200, 9000, 14000, 14100, 14600, 14900, 15400, 37500}

# The modes test.sh runs through its self-test vector path in a normal run (test.sh SELFTEST_MODES):
# no .pm and no .py oracle, so the ground truth is the module's own example hash read from
# --hash-info. 23800 is the only member today. -S runs the same path over every mode.

SELFTEST_MODES = {23800}

# test.sh caps a -S sweep at --runtime 60 rather than the usual 400, since a mode that has not
# cracked by then is not going to (test.sh).

SELFTEST_RUNTIME = 60

# Modes with no meaningful self-test crack: 2000 and 99999 are Plaintext passthrough modes (STDOUT),
# and 14600 is LUKS, whose example hash is N/A and lives in external container files. The sweep still
# runs them and prints their line, but does not count them as cracked or as a failure. test.sh keeps
# the same set (selftest_vector_sweep), so the two stay comparable.
NO_SELFTEST = {2000, 14600, 99999}

# test.sh's attack order for -a all (test.sh). A slow mode only runs the attacks that
# cost one candidate per word (the whole word attacks), so it gets 0, 4, 8 and 9 and nothing else,
# even when another attack is asked for by number.

ATTACK_ORDER = [0, 4, 8, 9, 1, 3, 6, 7, 12]
WHOLE_WORD   = (0, 4, 8, 9)

# SLOW_ALGOS is every module with ATTACK_EXEC_OUTSIDE_KERNEL plus these, whose generated passwords
# the mask attacks cannot express (test.sh). 400 is run as a fast hash on purpose, to cover
# the AMP kernel (test.sh).

FAKE_SLOW = {28501, 28502, 28503, 28504, 28505, 28506, 30901, 30902, 30903, 30904, 30905, 30906,
             34700}

# The oracle writes one shell line per vector: echo <word> | ./hashcat ${OPTS} -a 0 -m <n> '<h>'.
# The word is padded to 31 with trailing spaces by the "%-31s" the oracle uses; the hash is single
# quoted and holds no single quote of its own.

LINE = re.compile(rb"^echo (.*) \| \./hashcat \$\{OPTS\} -a 0 -m \d+ '(.*)'$")

# -a 4 asks the pcfg device engine for OpenCL/mNNNNN_a4-optimized.cl by the mode's kern_type, not by
# the mode number, so the file test is on the kern_type read out of the module (test.sh).

KERN_TYPE_RE = re.compile(rb"^static const u64\s+KERN_TYPE\s+=\s*([0-9]+)", re.M)

DEVICE_LABEL = {"1": "Cpu", "2": "Gpu", "3": "Fpga"}


def die(msg):
  sys.stderr.write(msg + "\n")

  sys.exit(1)


def discover_modes():
  out = []

  for path in glob.glob(os.path.join(TDIR, "test_modules", "m[0-9][0-9][0-9][0-9][0-9].py")):
    out.append(int(re.search(r"m0*([0-9]+)\.py$", path).group(1)))

  return sorted(set(out))


def select_modes(spec, modes):
  # test.sh's -m rules: a single value must be a member, a range must intersect the set and may
  # span gaps, "all" is every member.

  # A SELFTEST_MODES member has no .py oracle but is still selectable, because test.sh runs its
  # self-test vector in a normal run (test.sh). Fold it into the set so a single -m 23800, a
  # range that spans it, and "all" all accept it; the main loop then picks the self-test path for a
  # mode that has no .py.

  modes = sorted(set(modes) | SELFTEST_MODES | CONTAINER_MODES)

  if spec == "all":
    return modes

  if re.fullmatch(r"[0-9]+", spec):
    ht = int(spec)

    if ht not in modes:
      die("! hash type %d has no tools/test_modules/m%05d.py, so test.py cannot run it\n"
          "! modes with a python oracle: %s" % (ht, ht, " ".join(str(m) for m in modes)))

    return [ht]

  m = re.fullmatch(r"([0-9]+)-([0-9]+)", spec)

  if m is None:
    die("! invalid hash type selected: %s" % spec)

  lo, hi = int(m.group(1)), int(m.group(2))

  if lo > hi:
    die("! invalid hash type range: %d-%d" % (lo, hi))

  hit = [ht for ht in modes if lo <= ht <= hi]

  if not hit:
    die("! no hash type between %d and %d has a python oracle\n"
        "! modes with a python oracle: %s" % (lo, hi, " ".join(str(m) for m in modes)))

  return hit


def module_source(mode):
  try:
    with open(os.path.join(ROOT, "src", "modules", "module_%05d.c" % mode), "rb") as fh:
      return fh.read()
  except OSError:
    return b""


def is_file_only(mode):
  return b"OPTS_TYPE_BINARY_HASHFILE" in module_source(mode)


def is_bridged(mode):
  # A bridged mode does its hashing on an assimilation bridge (a Python interpreter for 73000),
  # named by BRIDGE_NAME in the module. The bridge hardware is chosen by the hash-mode, never by -D.
  return b"BRIDGE_NAME" in module_source(mode)


def cpu_backend_id():
  # The backend device number of the first CPU device, or None. Looked up once and cached, since it
  # shells out to -I.
  global CPU_BACKEND_ID

  if CPU_BACKEND_ID != -1:
    return CPU_BACKEND_ID

  CPU_BACKEND_ID = next((d["id"] for d in backend_devices() if d["type"] == "CPU"), None)

  return CPU_BACKEND_ID


def bridge_opts(mode):
  # For a bridged mode the bridge does the hashing, but hashcat still needs a real device to generate
  # candidates and host the bridge's virtual instances. That device has to survive -D first: the
  # default -D 2 keeps only GPUs and drops the CPU the host role falls to, so the run has no device
  # left and every case errors (this is what a headless box hits). --backend-devices-virthost only
  # picks among the devices -D kept, it cannot bring a dropped one back, so -D itself is set to the
  # CPU here and virthost is pinned to the CPU's own number, which stays correct when the CPU is not
  # backend device #1. These override the run's -D, appended last so they win; -D never selects the
  # bridge's own hardware anyway.
  #
  # On a box with no CPU backend at all there is nothing to move the host role to, and -D 1 would
  # drop the one device that could have done it, so the run keeps the -D it came with instead. That
  # is a plain GPU install, where -D 2 hosts the bridge on the GPU and the cases pass.
  if not is_bridged(mode):
    return []

  cid = cpu_backend_id()

  if cid is None:
    return []

  return ["-D", "1", "--backend-devices-virthost", str(cid)]


def device_for(args, mode):
  # The device type a mode actually runs on: the CPU for a bridged mode (see bridge_opts), the run's
  # -D otherwise. Used for the reported Device-Type so the line matches what ran. The condition is
  # the one bridge_opts uses, because a bridged mode on a box with no CPU backend stays on the -D it
  # came with and the line has to say so.
  if is_bridged(mode) and (cpu_backend_id() is not None):
    return "1"

  return args.device


def is_slow(mode):
  if mode == 400:
    return False

  return mode in FAKE_SLOW or b"ATTACK_EXEC_OUTSIDE_KERNEL" in module_source(mode)


def host_engine(mode):
  # test.sh HOST_ENGINE_ALGOS is the plain ATTACK_EXEC_OUTSIDE_KERNEL set (test.sh), taken before
  # the fake-slow additions, so it is read straight off the module and does not carry FAKE_SLOW.

  return b"ATTACK_EXEC_OUTSIDE_KERNEL" in module_source(mode)


def is_timeout(mode):
  # test.sh TIMEOUT_ALGOS is SLOW_ALGOS as written (test.sh), which keeps 400 that is_slow drops
  # for attack selection. It caps a single-hash whole-word run at 12 vectors instead of 32.

  return mode in FAKE_SLOW or host_engine(mode)


def a4_optimized(mode):
  # Whether the mode ships an optimized pcfg kernel, named by its kern_type (test.sh).

  m = KERN_TYPE_RE.search(module_source(mode))

  if m is None:
    return False

  return os.path.isfile(os.path.join(ROOT, "OpenCL", "m%05d_a4-optimized.cl" % int(m.group(1))))


def a4_optimized_skip(mode, optimized):
  # test.sh: an optimized -a 4 pass on a mode whose kernel runs inside the device and that ships
  # no optimized pcfg kernel would be refused by hashcat, so the pass is skipped and, unlike a normal
  # skip, prints no summary line. The pure pass covers the attack for such a mode.

  return optimized and not host_engine(mode) and not a4_optimized(mode)


def has_multi_hash(mode):
  return mode in MULTI_ONE_HASH


def oracle_spare(mode, optimized, length):
  # test.sh whole_word_vectors: one vector of a fixed length from the same oracle, to stand in for
  # a word -a 4 cannot express. Returns (word, digest) or None.

  env = dict(os.environ)
  env["IS_OPTIMIZED"] = "1" if optimized else "0"

  proc = subprocess.run([sys.executable, RUNNER, "spare", str(mode), str(length)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  if proc.returncode != 0:
    return None

  for line in proc.stdout.splitlines():
    m = LINE.match(line)

    if m is not None:
      return (m.group(1).rstrip(b" "), m.group(2).decode("ascii"))

  return None


def a4_vectors(mode, pairs, optimized):
  # test.sh whole_word_vectors (test.sh): a grammar builds its candidate out of terminals of at
  # least one character, so the zero length word the -a 0 vectors carry for a min-zero mode cannot be
  # written into a ruleset. Where one is present it is swapped for a spare word of length 1 and the
  # hash that goes with it. Returns the substituted pairs, or None to fall back to the -a 0 vectors,
  # which is what an empty _a4.sh means in test.sh (no empty word, a LUKS or 10300 list, or no spare).

  if not pairs:
    return None

  if mode in LUKS_MODES or mode == 10300:
    return None

  if not any(word == b"" for word, _ in pairs):
    return None

  spare = oracle_spare(mode, optimized, 1)

  if spare is None or spare[0] == b"":
    return None

  return [spare if word == b"" else (word, digest) for word, digest in pairs]


def attacks_for(spec, mode):
  wanted = ATTACK_ORDER if spec == "all" else [int(spec)]

  if mode in MASK_ONLY_MODES:
    return [a for a in wanted if a == 3]

  if is_slow(mode):
    wanted = [a for a in wanted if a in WHOLE_WORD]

  return wanted


def decode_hashfile(mode, digest):
  # test.sh/1062: the base64 decodes to the file hashcat reads. 22000/22001 are handed their
  # line as is instead.

  if mode in (22000, 22001):
    return (digest + "\n").encode("ascii")

  return base64.b64decode(digest)


def oracle_vectors(mode, optimized):
  # Generate this mode's vectors with the same engine test.sh's run_oracle uses. Exit code 2 means
  # the mode has no kernel for the requested family, which is a Skip and not a failure.

  env = dict(os.environ)
  env["IS_OPTIMIZED"] = "1" if optimized else "0"

  proc = subprocess.run([sys.executable, RUNNER, "single", str(mode)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  if proc.returncode == 2:
    return None

  if proc.returncode != 0:
    die("! oracle failed for mode %d (rc=%d):\n%s"
        % (mode, proc.returncode, proc.stderr.decode("utf-8", "replace").rstrip()))

  pairs = []

  for line in proc.stdout.splitlines():
    m = LINE.match(line)

    if m is None:
      continue

    # The word carries the "%-31s" padding, stripped here. A password that itself ends in a space
    # cannot survive this format and is out of scope, the same limitation test.sh has; the modes
    # with a .py today use numeric passwords.
    #
    # A hash is assumed to be 7 bit ASCII across the suite, so it is decoded as ASCII here and
    # encoded back as ASCII wherever it is written or compared. A mode whose hash is its own
    # plaintext (the passthrough mode 99999) keeps its generated password ASCII so this holds.

    pairs.append((m.group(1).rstrip(b" "), m.group(2).decode("ascii")))

  return pairs


def classify(rc, matched, c):
  # A hashcat run that exits 0 but whose output does not carry the pair is rewritten to code 10, then
  # the code is bucketed as test.sh's status() did: 1 exhausted, 4 --runtime, 10 not matched, the
  # runtime-skip codes to skipped. The one deviation: test.sh sent every other
  # code, 255 (cuMemAlloc out of memory) and a signal crash included, to not found, so a worker that
  # never got its memory read the same as one that ran and missed the password. Those go to err
  # instead, a hard error kept apart from a failed crack. The skip set is spelled out, not a range,
  # because 247 is not a skip; it lands in err with the rest.

  c["cnt"] += 1

  ret = (0 if matched else 10) if rc == 0 else rc

  log_result(ret)

  if ret == 0:
    return

  if ret == 1:
    c["nf"] += 1
  elif ret == 4:
    c["to"] += 1
  elif ret == 10:
    c["nm"] += 1
  elif ret == 30 or ret in (246, 248, 249, 250, 251, 252, 253):
    c["rs"] += 1

    if ret == 252 and os.environ.get("HASHCAT_DEVICE_MEM_LIMIT"):
      # A memory skip while a per-worker cap is in force is a property of the -j run, not the mode, so
      # flag it for run_parallel to retry without the cap.
      global CAPPED_MEM_SKIP
      CAPPED_MEM_SKIP = True
  else:
    c["err"] += 1


def verdict(c):
  # A hard error outranks the rest: it is the one result that is not about whether
  # the mode cracked. The order below it is test.sh's.
  if c.get("err"):
    return "Fault"

  if c["rs"]:
    return "Skip"

  if c["nf"] or c["nm"] or c["cnt"] == 0:
    return "Error"

  if c["to"]:
    return "Warning"

  return "OK"


def run_hashcat(opts, mode, target, stdin_bytes, attack=0, extra=()):
  global LAST_CMD

  cmd = [BIN] + opts + bridge_opts(mode) + ["-a", str(attack), "-m", str(mode), target] + list(extra)
  LAST_CMD = cmd

  # Run from the repo root, the way test.sh does, so hashcat finds OpenCL/ and caches kernels/
  # there rather than in whatever directory the manager was invoked from.

  proc = subprocess.run(cmd, input=stdin_bytes, cwd=ROOT,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  out = proc.stdout + proc.stderr
  log_output(cmd, out)

  return proc.returncode, out


def context(args, mode, target_name, width, attack=0):
  # test.sh pads the multi label with a second space so the Device-Type column lines up under the
  # longer "single" (test.sh vs 1187). Kept so the part after the leading label matches it
  # byte for byte.

  mode_field = "single, " if target_name == "single" else "multi,  "

  dev = device_for(args, mode)

  return ("[ test.py ] [ Type %d, Attack %d, Mode %sDevice-Type %s, Kernel-Type %s, Vector-Width %d ]"
          % (mode, attack, mode_field, DEVICE_LABEL.get(dev, dev),
             "Pure" if args.pure else "Optimized", width))


def report(args, mode, target_name, width, c, attack=0):
  v = verdict(c)

  line = ("%s > %s : %d/%d not found, %d/%d not matched, %d/%d timeout, %d/%d skipped"
          % (context(args, mode, target_name, width, attack), v,
             c["nf"], c["cnt"], c["nm"], c["cnt"], c["to"], c["cnt"], c["rs"], c["cnt"]))

  # An errors field is added only when there is one, so a run without a hard error prints the exact
  # test.sh line and the four-way equivalence still holds byte for byte.
  if c.get("err"):
    line += ", %d/%d errors" % (c["err"], c["cnt"])

  print(line)
  record(v)
  note_verdict(v)


def report_skip(args, mode, target_name, width, reason, attack=0):
  print("%s > Skip : %s" % (context(args, mode, target_name, width, attack), reason))


def match_search(digest, word, pass_only):
  # test.sh: normally the recovered line is hash:password; for a file based or
  # encoding-exception mode only the password half is ours to check.

  if pass_only:
    return b":" + word

  return digest.encode("ascii") + b":" + word


def run_single(opts, mode, pairs, args, width, file_only, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  temp_file = os.path.join(tmp, "m%05d_filebased.bin" % mode)

  for word, digest in pairs[:SINGLE_MAX]:
    if file_only:
      with open(temp_file, "wb") as fh:
        fh.write(decode_hashfile(mode, digest))

      target = temp_file
    else:
      target = digest

    candidate = word

    if mode == 20510:
      # PKZIP master key, 6 byte optimization: hashcat is fed the key without its first 6 bytes and
      # reconstructs the whole password in the crack line, which output_has_crack still matches
      # against the full word. The other attacks already cut the word the same way.
      candidate = word[6:]

    rc, out = run_hashcat(opts, mode, target, candidate + b"\n")

    matched = output_has_crack(mode, out, word, digest, pass_only, tmp)

    classify(rc, matched, c)

  report(args, mode, "single", width, c)


def run_multi(opts, mode, pairs, args, width, file_only, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  hash_file = os.path.join(tmp, "m%05d_hashes.txt" % mode)

  if file_only:
    # test.sh: every base64 hash decoded and concatenated into one file (22000/22001 keep their
    # raw line), the way decode_hashfile splits it.
    with open(hash_file, "wb") as fh:
      for _, digest in pairs:
        fh.write(decode_hashfile(mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in pairs) + b"\n")

  stdin_bytes = b"\n".join(w for w, _ in pairs) + b"\n"

  rc, out = run_hashcat(opts, mode, hash_file, stdin_bytes)

  # test.sh scores the whole batch as one test: one hashcat run, every pair has to be in the
  # output, and status is called once (test.sh). So the count here is 1, not one per hash
  # the way single is, and classify does the "cracked but a pair is missing" rewrite.

  matched = all(output_has_crack(mode, out, word, digest, pass_only, tmp) for word, digest in pairs)

  classify(rc, matched, c)

  report(args, mode, "multi", width, c)


class Run:
  # What one attack function needs for one mode at one vector width.

  def __init__(self, args, mode, pairs, width, opts, targets, file_only, pass_only, tmp):
    self.args      = args
    self.mode      = mode
    self.pairs     = pairs
    self.width     = width
    self.opts      = opts
    self.targets   = targets
    self.file_only = file_only
    self.pass_only = pass_only
    self.tmp       = tmp


def attack_0(r):
  # test.sh attack_whole_word 0: the word on stdin, single then multi.

  if "single" in r.targets:
    run_single(r.opts, r.mode, r.pairs, r.args, r.width, r.file_only, r.pass_only, r.tmp)

  if "multi" in r.targets:
    # test.sh gives the has_multi_hash modes one hash each, so there is no multi run and no line.
    # Everything else, binary hashfile included, runs one multi as test.sh does (its has_multi_hash
    # list omits the binary hashfile modes, so for those it runs a one-hash multi that ends Error).
    if has_multi_hash(r.mode):
      return

    run_multi(r.opts, r.mode, r.pairs, r.args, r.width, r.file_only, r.pass_only, r.tmp)


def build_ruleset(ruleset_dir, words):
  # test.sh whole_word_ruleset (test.sh): the smallest pcfg that emits exactly this word list. X
  # is the flat token, so X1 at probability 1 is one terminal per entry, each carrying its own length,
  # all living in Context/1.txt. The run is then as long as the list and emits nothing else.

  shutil.rmtree(ruleset_dir, ignore_errors=True)

  os.makedirs(os.path.join(ruleset_dir, "Grammar"))
  os.makedirs(os.path.join(ruleset_dir, "Context"))

  with open(os.path.join(ruleset_dir, "Grammar", "grammar.txt"), "wb") as fh:
    fh.write(b"X1\t1.0\n")

  with open(os.path.join(ruleset_dir, "Context", "1.txt"), "wb") as fh:
    for word in words:
      fh.write(word + b"\t1.0\n")


def whole_word_source(attack, words_file, ruleset_dir):
  # test.sh whole_word_source (test.sh): the argv each whole-word attack takes after the hash. -a
  # 8 names the wordlist feed and its file, -a 9 the file pairing word N with hash N, -a 4 the ruleset
  # directory. -a 0 pipes its words in and is handled by attack_0.

  if attack == 4:
    return [ruleset_dir]

  if attack == 8:
    return ["wordlist", words_file]

  if attack == 9:
    return [words_file]

  return []


def whole_word_single(r, attack):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  optimized = not r.args.pure

  if attack == 4:
    subst   = a4_vectors(r.mode, r.pairs, optimized)
    vectors = subst if subst is not None else r.pairs
  else:
    vectors = r.pairs

  # test.sh: a single-hash run stops at 32 vectors, or 12 for a slow mode.

  max_n = 12 if is_timeout(r.mode) else 32

  temp_file   = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  words_file  = os.path.join(r.tmp, "m%05d_a%d_words" % (r.mode, attack))
  ruleset_dir = os.path.join(r.tmp, "m%05d_a%d_ruleset" % (r.mode, attack))

  for word, digest in vectors[:max_n]:
    candidate = word

    if r.mode == 20510:
      # PKZIP master key: hashcat is fed the key without its 6 byte prefix, the recovered line still
      # carries the whole password (test.sh).
      candidate = word[6:]

    if attack == 4 and len(candidate) == 0:
      # A ruleset cannot write an empty candidate, so it is skipped rather than run (test.sh).
      c["rs"]  += 1
      c["cnt"] += 1

      continue

    if r.file_only:
      with open(temp_file, "wb") as fh:
        fh.write(decode_hashfile(r.mode, digest))

      target = temp_file
    else:
      target = digest

    with open(words_file, "wb") as fh:
      fh.write(candidate + b"\n")

    if attack == 4:
      build_ruleset(ruleset_dir, [candidate])

    extra = whole_word_source(attack, words_file, ruleset_dir)

    rc, out = run_hashcat(r.opts, r.mode, target, None, attack=attack, extra=extra)

    matched = output_has_crack(r.mode, out, word, digest, r.pass_only, r.tmp)

    classify(rc, matched, c)

  report(r.args, r.mode, "single", r.width, c, attack)


def whole_word_multi(r, attack):
  # test.sh: the modes with one hash each have no multi-hash run, -a 9 gives one candidate per
  # salt so its multi case is left to test_edge.sh, and a binary hashfile has no line to drop so -a 4
  # keeps its single coverage only.

  if has_multi_hash(r.mode):
    return

  if attack == 9:
    return

  if attack == 4 and r.file_only:
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  optimized = not r.args.pure

  if attack == 4:
    # test.sh: -a 4 runs on the substituted list, or on the -a 0 list with the empty word
    # dropped where no spare could be drawn.
    subst  = a4_vectors(r.mode, r.pairs, optimized)
    mpairs = subst if subst is not None else [(w, d) for w, d in r.pairs if w != b""]
  else:
    mpairs = r.pairs

  hash_file   = os.path.join(r.tmp, "m%05d_hashes.txt" % r.mode)
  words_file  = os.path.join(r.tmp, "m%05d_a%d_multi_words" % (r.mode, attack))
  ruleset_dir = os.path.join(r.tmp, "m%05d_a%d_multi_ruleset" % (r.mode, attack))

  if r.file_only:
    # test.sh: every base64 hash decoded and concatenated into one file, the raw line kept for
    # 22000/22001. decode_hashfile carries that split.
    with open(hash_file, "wb") as fh:
      for _, digest in mpairs:
        fh.write(decode_hashfile(r.mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in mpairs) + b"\n")

  with open(words_file, "wb") as fh:
    fh.write(b"\n".join(w for w, _ in mpairs) + b"\n")

  if attack == 4:
    build_ruleset(ruleset_dir, [w for w, _ in mpairs])

  extra = whole_word_source(attack, words_file, ruleset_dir)

  rc, out = run_hashcat(r.opts, r.mode, hash_file, None, attack=attack, extra=extra)

  # As with -a 0 multi, one hashcat run scored as one test: every pair must be in the output.

  matched = all(output_has_crack(r.mode, out, word, digest, r.pass_only, r.tmp) for word, digest in mpairs)

  classify(rc, matched, c)

  report(r.args, r.mode, "multi", r.width, c, attack)


def whole_word(r, attack):
  if attack == 4 and a4_optimized_skip(r.mode, not r.args.pure):
    # No summary line at all, the same as test.sh which logs the skip to logfull only (test.sh).
    return

  if "single" in r.targets:
    whole_word_single(r, attack)

  if "multi" in r.targets:
    whole_word_multi(r, attack)


def attack_4(r):
  whole_word(r, 4)


def attack_8(r):
  whole_word(r, 8)


def attack_9(r):
  whole_word(r, 9)


def utf8_split_point(text, off):
  # test.sh utf8_split_point (byte offsets, since test.sh runs under LC_ALL=C). Move the split
  # back to a UTF-8 boundary so each half is valid on its own; if that lands on 0 for a real
  # split, a character sits at the very start, so go forward to the next boundary instead. The
  # .py oracle passwords are ASCII for most modes, where this returns off unchanged, but 20510
  # uses multi byte passwords, so the boundary handling matters there.

  n = len(text)
  back = off

  while back > 0 and back < n and 0x80 <= text[back] <= 0xbf:
    back -= 1

  if back == 0 and off > 0:
    while off < n and 0x80 <= text[off] <= 0xbf:
      off += 1

    return off

  return back


def combinator_init_params(mode):
  # init()'s per mode line skip and split offset for the single-build dicts (test.sh).
  # init_min lines are left out of the dicts, min_offset shifts the split toward the tail.

  init_min = 1
  min_offset = 0

  if mode == 2500:
    min_offset = 7
  elif mode == 14000:
    init_min = 0
    min_offset = 4
  elif mode == 14100:
    init_min = 0
    min_offset = 3
  elif mode == 14900:
    init_min = 0
    min_offset = 5
  elif mode == 15400:
    init_min = 0
    min_offset = 3
  elif mode == 16800:
    min_offset = 7
  elif mode == 22000:
    min_offset = 7

  return init_min, min_offset


def split_for_combinator(pairs, mode):
  # Reproduce init()'s dict1/dict2 build (test.sh) as two byte-string lists, one line per
  # password whose 1-based index exceeds init_min. dict1[k] . dict2[k] is that kept password, so
  # the combinator concatenates the halves back to the word. Kept in its own helper because -a 6
  # and -a 7 reuse the same split.

  init_min, min_offset = combinator_init_params(mode)

  dict1 = []
  dict2 = []
  i = 0

  for word, _ in pairs:
    i += 1

    if i <= init_min:
      continue

    p0 = i // 2
    p1 = p0 + 1
    pass_len = len(word)

    if pass_len > 1:
      p1 += min_offset
      p0 += min_offset

      if p1 > pass_len:
        p1 = pass_len
        p0 = p1 - 1

      p0 = utf8_split_point(word, p0)

      dict1.append(word[:p0])
      dict2.append(word[p0:])
    elif pass_len == 1:
      dict1.append(word)
      dict2.append(b"")
    else:
      dict1.append(b"")
      dict2.append(b"")

  return dict1, dict2


def combinator_single_range(mode):
  # attack_1 single processes hashes whose 1-based index is in (min, max] (test.sh).

  smin, smax = 1, 8

  if mode in (14000, 14100, 14900, 15400):
    smin, smax = 0, 5
  elif mode == 20510:
    smin = 2

  return smin, smax


def combinator_multi_offset(mode):
  # attack_1 multi takes the last offset hashes as one batch (test.sh).

  if mode in (5800, 3000):
    return 6

  return 7


def pkzip_masterkey_dicts(dict1, dict2, line_nr):
  # test.sh, PKZIP master key. Rebuild the two dicts with line line_nr replaced by the
  # split the mode needs: the first 6 bytes of dict1 are dropped, and when dict1 is shorter than
  # 6 bytes the remainder is stolen from dict2. The search still uses the unmodified halves, so
  # only the run dicts change here. head/echo/tail in test.sh drops the line just after line_nr;
  # that quirk is kept so the combinator cross product is byte identical.

  idx = line_nr - 1
  d1 = dict1[idx]
  d2 = dict2[idx]

  if len(d1) >= 6:
    new_d1 = d1[6:]
    new_d2 = d2
  else:
    num_to_steal = 6 - len(d1)
    num_steal_start = num_to_steal + 1

    if len(d2) >= 6:
      num_to_steal_new = (len(d2) - num_to_steal) // 2

      if num_to_steal_new > num_to_steal:
        num_to_steal = num_to_steal_new

    new_d1 = d2[:num_to_steal][num_steal_start - 1:]
    new_d2 = d2[num_to_steal:]

  out1 = dict1[:idx] + [new_d1] + dict1[idx + 2:]
  out2 = dict2[:idx] + [new_d2] + dict2[idx + 2:]

  return out1, out2


def write_dict(path, lines):
  with open(path, "wb") as fh:
    for line in lines:
      fh.write(line + b"\n")


def run_combinator_single(r, dict1_lines, dict2_lines, dict1_path, dict2_path):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  smin, smax = combinator_single_range(r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  mod1_path = os.path.join(r.tmp, "m%05d_dict1_mod" % r.mode)
  mod2_path = os.path.join(r.tmp, "m%05d_dict2_mod" % r.mode)

  i = 0

  for word, digest in r.pairs:
    i += 1

    if i > smin:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      d1p, d2p = dict1_path, dict2_path

      if r.mode == 20510:
        # dict line for this hash: min 0 counts from 1, otherwise it trails the hash by one
        # because init() left the length 1 line out (test.sh).
        if smin == 0:
          line_nr = i
        elif i > 1:
          line_nr = i - 1
        else:
          line_nr = 1

        out1, out2 = pkzip_masterkey_dicts(dict1_lines, dict2_lines, line_nr)

        write_dict(mod1_path, out1)
        write_dict(mod2_path, out2)

        d1p, d2p = mod1_path, mod2_path

      rc, out = run_hashcat(r.opts, r.mode, target, b"", attack=1, extra=[d1p, d2p])

      # dict1[k] . dict2[k] reconstructs the word, so the expected plain is the password itself,
      # the same string -a 0 searches for (test.sh).

      matched = output_has_crack(r.mode, out, word, digest, r.pass_only, r.tmp)

      classify(rc, matched, c)

    if i == smax:
      break

  report(r.args, r.mode, "single", r.width, c, attack=1)


def run_combinator_multi(r, dict1_path, dict2_path):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  offset = combinator_multi_offset(r.mode)
  sel = r.pairs[-offset:]

  hash_file = os.path.join(r.tmp, "m%05d_multihash_combi.bin" % r.mode)

  if r.file_only:
    # test.sh concatenates the decoded files with no separator (test.sh). Reached only
    # if a non-slow binary hashfile mode ever gains a .py oracle; today none do.
    with open(hash_file, "wb") as fh:
      for _, digest in sel:
        fh.write(decode_hashfile(r.mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in sel) + b"\n")

  rc, out = run_hashcat(r.opts, r.mode, hash_file, b"", attack=1, extra=[dict1_path, dict2_path])

  # One hashcat run scored as one test (test.sh): every selected pair has to be in the
  # output, and each expected plain is the password because the halves rejoin to it.

  matched = all(output_has_crack(r.mode, out, word, digest, r.pass_only, r.tmp) for word, digest in sel)

  classify(rc, matched, c)

  report(r.args, r.mode, "multi", r.width, c, attack=1)


def attack_1(r):
  # test.sh attack_1: the combinator. The word list is split into dict1 (left) and dict2 (right)
  # so hashcat concatenates them back, single hash then multi hash.

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  dict1_path = os.path.join(r.tmp, "m%05d_dict1" % r.mode)
  dict2_path = os.path.join(r.tmp, "m%05d_dict2" % r.mode)

  write_dict(dict1_path, dict1_lines)
  write_dict(dict2_path, dict2_lines)

  if "single" in r.targets:
    run_combinator_single(r, dict1_lines, dict2_lines, dict1_path, dict2_path)

  if "multi" in r.targets and not has_multi_hash(r.mode):
    run_combinator_multi(r, dict1_path, dict2_path)


def mask_dots(count):
  # test.sh mask_dots (test.sh): a mask of <count> '?d' groups.

  return b"?d" * count


def mask_3(pos):
  # test.sh mask_3[] (test.sh): 'pos' '?d' groups, but never more than 15 of them; the length
  # beyond position 15 is spelled with literal '0's instead.

  if pos <= 15:
    return b"?d" * pos

  return b"?d" * 15 + b"0" * (pos - 15)


def mask_literalize(mask, text):
  # test.sh mask_literalize (test.sh): rewrite a mask so each position spells the byte that
  # belongs there. A '?x' group and a bare byte each cover one position. If the mask does not cover
  # exactly len(text) bytes it is returned untouched; otherwise a position keeps its token when the
  # matching byte is an ASCII digit and becomes that literal byte otherwise, so a '?d' run can spell
  # a password that carries a multi byte character no '?d' produces.

  tokens = []
  pos = 0

  while pos < len(mask):
    if mask[pos:pos + 1] == b"?":
      tokens.append(mask[pos:pos + 2])
      pos += 2
    else:
      tokens.append(mask[pos:pos + 1])
      pos += 1

  if len(tokens) != len(text):
    return mask

  out = b""

  for k, tok in enumerate(tokens):
    byte = text[k:k + 1]

    if b"0" <= byte <= b"9":
      out += tok
    else:
      out += byte

  return out


def run_verify(mode, digest, crack_lines, tmp):
  # test.sh output_has_crack fallback (test.sh): hand the module's own verify the crack lines
  # that carry this hash and let it say whether one of them hashes back to it.

  hashes_file = os.path.join(tmp, "m%05d_verify_hashes" % mode)
  cracks_file = os.path.join(tmp, "m%05d_verify_cracks" % mode)
  out_file    = os.path.join(tmp, "m%05d_verify_out" % mode)

  with open(hashes_file, "wb") as fh:
    fh.write(digest.encode("ascii") + b"\n")

  with open(cracks_file, "wb") as fh:
    for line in crack_lines:
      fh.write(line + b"\n")

  open(out_file, "wb").close()

  subprocess.run([sys.executable, RUNNER, "verify", str(mode), hashes_file, cracks_file, out_file],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  return os.path.getsize(out_file) > 0


def output_has_crack(mode, out, word, digest, pass_only, tmp):
  # test.sh output_has_crack (test.sh). The recovered line hash:password is looked for as it was
  # generated first. A mode that drops bits of the password can print a different password with the
  # same hash, so DES for one keeps 7 bits per byte, and a line that is not there verbatim is
  # re-checked by hash through the module's verify. A password only search has no hash to verify
  # against and stops at the plain comparison.

  if match_search(digest, word, pass_only) in out:
    return True

  # A mode that always hexifies writes its plaintext as bare hex, so the recovered line carries the
  # hex of the password rather than its bytes. The edge suite compares the same way.

  if edge_hexify_plain(mode):
    if match_search(digest, word.hex().encode("ascii"), pass_only) in out:
      return True

  if mode in MFULC_MODES:
    if digest.encode("ascii") + b":" in out:
      return True

  if pass_only:
    # hashcat prints a password it considers unprintable as $HEX[...], so a pass-only match, which
    # has no hash to fall back on, accepts that form of the same bytes too.
    if b":$HEX[" + word.hex().encode("ascii") + b"]" in out:
      return True

    return False

  prefix = digest.encode("ascii") + b":"
  crack_lines = [line for line in out.split(b"\n") if prefix in line]

  if not crack_lines:
    return False

  return run_verify(mode, digest, crack_lines, tmp)


def a3_single_max(mode):
  # test.sh attack_3 single (test.sh): the number of hashes a single-hash run covers. Some
  # modes cap it lower because they carry a minimum password length.

  if mode in (14000, 14100, 14900, 15400):
    return 1

  if mode in (2500, 16800, 22000):
    return 7

  return 8


def a3_single_mask(mode, word, i):
  # test.sh attack_3 single mask (test.sh): the first i bytes become a '?d' run rewritten to
  # spell them and the rest of the password trails as literals. 14000 and 14100 hand hashcat the
  # whole password as a literal mask instead, and 20510 drops the leading groups the mode does not
  # keep.

  if mode in (14000, 14100):
    return word

  if mode == 20510:
    # PKZIP master key, 6 byte optimization: the kernel is fed the password with its first 6 bytes
    # dropped and reconstructs them, so the mask has to spell that stripped candidate, not the whole
    # word. Build it over the candidate directly, byte by byte, rather than cutting a literalized
    # whole word mask by a fixed offset. The offset form miscounts whenever a non-digit byte sits in
    # the first 6 bytes, since mask_literalize spells a non-digit as a one character literal while a
    # '?d' group is two, so the cut lands wrong and the mask spells the wrong candidate. Brute force
    # the leading positions the index reaches past the 6 byte cut; spell the rest literally.
    cand = word[6:]
    nd   = max(i - 6, 0)

    if nd > len(cand):
      nd = len(cand)

    return mask_literalize(mask_dots(nd), cand[:nd]) + cand[nd:]

  return mask_literalize(mask_dots(i), word[:i]) + word[i:]


def attack_3_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  max_i     = a3_single_max(r.mode)
  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)

  i = 1

  for word, digest in r.pairs:
    # test.sh: a slow mode stops after the sixth hash.
    if i > 6 and is_timeout(r.mode):
      break

    # test.sh: a mask cannot produce a password shorter than itself, so that hash is skipped
    # and does not count.
    if len(word) < i:
      i += 1

      continue

    # test.sh: PKZIP master key needs at least two '?d' groups to keep after the cut.
    if r.mode == 20510 and i <= 1:
      i += 1

      continue

    if r.file_only:
      with open(temp_file, "wb") as fh:
        fh.write(decode_hashfile(r.mode, digest))

      target = temp_file
    else:
      target = digest

    mask = a3_single_mask(r.mode, word, i)

    rc, out = run_hashcat(r.opts, r.mode, target, None, attack=3, extra=[mask])

    matched = output_has_crack(r.mode, out, word, digest, r.pass_only, r.tmp)

    classify(rc, matched, c)

    if i == max_i:
      break

    i += 1

  report(r.args, r.mode, "single", r.width, c, attack=3)


def a3_multi_increment(mode):
  # test.sh attack_3 multi (test.sh): the --increment window. A slow mode narrows it, and the
  # modes with a minimum password length move it up.

  increment_min = 1
  increment_max = 5 if is_timeout(mode) else 8

  if mode in (2500, 16800, 22000):
    increment_min = 8
    increment_max = 9

  return increment_min, increment_max


def a3_custom_charsets(mode, sel_passwords):
  # test.sh attack_3 multi (test.sh): 2500, 16800 and 22000 pin the mask to ?d?d?d?d?d?1?2?3?4
  # and build the -1..-4 charsets out of the bytes the passwords carry at positions 6, 7, 8 and 9.
  # All three run outside the kernel, so a mode-3 run never reaches this today; it is kept so the
  # port stays faithful to test.sh.

  if mode not in (2500, 16800, 22000):
    return []

  args = []

  for n, pos in ((1, 6), (2, 7), (3, 8), (4, 9)):
    if not sel_passwords:
      charset = str(n).encode("ascii")
    else:
      chars = set()

      for pw in sel_passwords:
        chars.add(pw[pos - 1:pos])

      charset = b"".join(sorted(chars))

    args += ["-%d" % n, charset]

  return args


def attack_3_multi(r):
  # test.sh: the modes with one hash each have no multi-hash run.
  if has_multi_hash(r.mode):
    return

  increment_min, increment_max = a3_multi_increment(r.mode)

  words   = [w for w, _ in r.pairs]
  digests = [d for _, d in r.pairs]

  head_hashes = sum(1 for w in words if len(w) <= increment_max)
  tail_hashes = sum(1 for w in words if increment_min <= len(w) <= increment_max)

  # test.sh: one --increment run cannot spell a password that carries a multi byte character,
  # so an hcmask file with one mask per password is used whenever a character is in play, and when
  # no password falls in the increment window at all.

  need_hcmask = 0

  if tail_hashes > head_hashes:
    need_hcmask = 1

  if any(b > 0x7f for w in words for b in w):
    need_hcmask = 2

  if tail_hashes < 1:
    need_hcmask = 1

  hash_file   = os.path.join(r.tmp, "m%05d_multihash_bruteforce.txt" % r.mode)
  hcmask_path = os.path.join(r.tmp, "m%05d_multi_a3.hcmask" % r.mode)
  dict_path   = os.path.join(r.tmp, "m%05d_passwords.txt" % r.mode)

  if need_hcmask in (0, 2):
    sel = list(range(head_hashes - tail_hashes, head_hashes))
  else:
    tail_hashes = sum(1 for w in words if len(w) >= increment_min)

    if tail_hashes < 1:
      return

    sel = list(range(len(words) - tail_hashes, len(words)))

  if r.file_only:
    with open(hash_file, "wb") as fh:
      for k in sel:
        fh.write(decode_hashfile(r.mode, digests[k]))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(digests[k].encode("ascii") for k in sel) + b"\n")

  mask_pos = max(8, increment_min)

  if need_hcmask == 2:
    cracks_offset = head_hashes - tail_hashes

    with open(hcmask_path, "wb") as fh:
      for w in words:
        if increment_min <= len(w) <= increment_max:
          fh.write(mask_literalize(mask_dots(len(w)), w) + b"\n")

    mask_arg = hcmask_path
  elif need_hcmask == 0:
    cracks_offset = head_hashes - tail_hashes
    mask_arg      = mask_3(mask_pos)
  else:
    cracks_offset = len(words) - tail_hashes

    with open(dict_path, "wb") as fh:
      for w in words:
        fh.write(w + b"\n")

    mask_arg = dict_path

  # The custom-charset modes replace the mask outright; increment_charset_opts carries the charsets
  # only on the plain --increment path (test.sh).

  custom = a3_custom_charsets(r.mode, words[:len(sel)])

  if r.mode in (2500, 16800, 22000):
    mask_arg = b"?d?d?d?d?d?1?2?3?4"

  increment_opts = []

  if need_hcmask == 0:
    increment_opts = ["--increment", "--increment-min", str(increment_min),
                      "--increment-max", str(increment_max)] + custom

  rc, out = run_hashcat(r.opts, r.mode, hash_file, None, attack=3,
                        extra=increment_opts + [mask_arg])

  # test.sh: one hashcat run scored as one test; every selected pair must be in the output,
  # matched by hash where the printed password differs from the generated one.

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  if rc == 0:
    matched = all(output_has_crack(r.mode, out, words[idx + cracks_offset], digests[k],
                                   r.pass_only, r.tmp)
                  for idx, k in enumerate(sel))
  else:
    matched = False

  classify(rc, matched, c)

  report(r.args, r.mode, "multi", r.width, c, attack=3)


def attack_3(r):
  # test.sh attack_3: the mask (brute force) attack. Each password is turned into a mask that
  # regenerates exactly it, single hash then multi hash.

  if "single" in r.targets:
    attack_3_single(r)

  if "multi" in r.targets:
    attack_3_multi(r)


# -a 6 and -a 7 are the two hybrid attacks, a wordlist on one side and a mask on the other. Both
# reuse the single-hash dict split from attack_1 (split_for_combinator) for their word halves and
# the mask helpers from attack_3. Their multi-hash runs need one more thing, a fresh batch of eight
# passwords per length split into a word file and a mask, the way test.sh init () builds
# dict1_multi/dict2_multi (test.sh). MULTI_CACHE holds each batch so a length is asked of the
# oracle once, not once per width and attack.

MULTI_CACHE = {}


def sed_line(lines, n):
  # test.sh reads a dict line with 'sed -n ${n}p', which prints nothing when n is past the end of
  # the file. Some hybrid special cases build a one line custom dict and then index it by a larger
  # line number, so an out of range read has to come back empty rather than raise.

  if 1 <= n <= len(lines):
    return lines[n - 1]

  return b""


def hybrid_extra(items):
  # test.sh passes the mask unquoted, so an empty mask expands to no argument at all rather than to
  # an empty one. Drop an empty byte string here to keep the same argv the shell would build. Only
  # the mask is ever bytes and ever empty; the dict paths are non-empty strings.

  return [x for x in items if not (isinstance(x, bytes) and x == b"")]


def multi_len_params(mode):
  # test.sh init () multi split (test.sh). min_len shifts the split toward the tail, and a
  # fixed_len mode draws every length slot at that one length except the slot that already matches.

  min_len   = 0
  fixed_len = 0

  if mode == 2500:
    min_len = 7
  elif mode == 14000:
    min_len = 7
  elif mode == 14100:
    min_len = 23
  elif mode == 14900:
    min_len = 9
  elif mode == 15400:
    min_len = 31
  elif mode == 16800:
    min_len = 7
  elif mode == 22000:
    min_len = 7
  elif mode in (9710, 9810, 10410):
    # Collider #1: the candidate is the 5 byte RC4 key, the only length the oracle makes. Without
    # a fixed length every slot but one asks for a length the mode has no vector for, so the multi
    # run feeds hashcat an empty hash file and, once the empty tail mask is dropped, no mask either,
    # which hashcat rejects. Pin every slot to length 5 so each builds a valid run.
    fixed_len = 5
  elif mode == 33500:
    fixed_len = 5
  elif mode == 33501:
    min_len   = 5
    fixed_len = 9
  elif mode == 33502:
    min_len   = 5
    fixed_len = 13
  elif mode == 36900:
    fixed_len = 8
  elif mode == 36901:
    fixed_len = 5
  elif mode == 37400:
    # pw_min is 9, so a length slot below it produces no vector and the multi run would feed
    # hashcat an empty hash file. Pin every slot to a valid length, and push the split toward the
    # tail so the mask the hybrid runs brute force stays one digit rather than the whole word. The
    # offset is 4 so the slot the a6/a12 multi runs (its head is 8 of the 9 bytes) still leaves a
    # one byte tail for the mask, since an empty mask would drop the argument and fail the run.
    min_len   = 4
    fixed_len = 9

  return min_len, fixed_len


def multi_pairs(mode, i, optimized):
  # test.sh init () (test.sh): the eight passwords for length slot i, from the same oracle
  # run_oracle uses. A fixed_len mode asks for fixed_len instead, except when the slot already is
  # that length. Empty when the requested length is outside the mode's word range, which is what an
  # empty _multi_${i} file is in test.sh.

  min_len, fixed_len = multi_len_params(mode)

  if fixed_len != 0:
    length = i if fixed_len == i else fixed_len
  else:
    length = i

  key = (mode, length, optimized)

  if key in MULTI_CACHE:
    return MULTI_CACHE[key]

  env = dict(os.environ)
  env["IS_OPTIMIZED"] = "1" if optimized else "0"

  proc = subprocess.run([sys.executable, RUNNER, "single", str(mode), str(length)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  pairs = []

  if proc.returncode == 0:
    for line in proc.stdout.splitlines():
      m = LINE.match(line)

      if m is not None:
        pairs.append((m.group(1).rstrip(b" "), m.group(2).decode("ascii")))

  MULTI_CACHE[key] = pairs

  return pairs


def build_multi_dicts(mode, i, pairs):
  # test.sh init () (test.sh): split each length-i password into dict1_multi (head) and
  # dict2_multi (tail) at i/2 + min_len, moved back to a UTF-8 boundary. The offset carries from one
  # password to the next exactly as the shell loop leaves it, which only matters once a split lands
  # inside a multi byte character.

  min_len, _ = multi_len_params(mode)

  p0 = i // 2 + min_len

  dict1 = []
  dict2 = []

  for word, _ in pairs:
    p0 = utf8_split_point(word, p0)

    dict1.append(word[:p0])
    dict2.append(word[p0:])

  return dict1, dict2


def write_hashes(path, pairs, mode, file_only):
  # The hash file a multi run reads: one digest per line, or the decoded binary hashfiles
  # concatenated for a file based mode. An empty batch gives an empty file, as test.sh's awk does.

  with open(path, "wb") as fh:
    for _, digest in pairs:
      if file_only:
        fh.write(decode_hashfile(mode, digest))
      else:
        fh.write(digest.encode("ascii") + b"\n")


def a6_single_params(mode):
  # test.sh attack_6 single (test.sh). mask_offset drives a first-line custom split that
  # attack_6 builds but never runs, so only min and max are read here.

  min_i, max_i = 1, 8

  if mode == 2500:
    max_i = 6
  elif mode in (14000, 14100, 14900, 15400):
    min_i, max_i = 0, 1
  elif mode == 16800:
    max_i = 6
  elif mode == 22000:
    max_i = 6

  return min_i, max_i


def attack_6_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i = a6_single_params(r.mode)

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict1_a6  = os.path.join(r.tmp, "m%05d_a6_dict1" % r.mode)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1

    # test.sh: a slow mode stops after the sixth hash.
    if i > 6 and is_timeout(r.mode):
      break

    if i > min_i:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      pass_b = word

      if r.mode == 20510:
        # PKZIP master key: hashcat is fed the key without its 6 byte prefix.
        pass_b = pass_b[6:]

      # test.sh: the index is the mask length, capped one byte below the password so a mode
      # with only short passwords still produces a case. A password that leaves no room for a word
      # is skipped and does not count.

      mask_len = i

      if mask_len >= len(pass_b):
        mask_len = len(pass_b) - 1

      if mask_len < 1:
        continue

      a6_split = utf8_split_point(pass_b, len(pass_b) - mask_len)

      # dict1 plus this one head word. test.sh shuffles the file here, which only reorders the
      # candidates hashcat tries them all, so the shuffle is left out.

      write_dict(dict1_a6, dict1_lines + [pass_b[:a6_split]])

      mask = mask_literalize(b"?d" * (len(pass_b) - a6_split), pass_b[a6_split:])

      rc, out = run_hashcat(r.opts, r.mode, target, None, attack=6,
                            extra=hybrid_extra([dict1_a6, mask]))

      # The search reconstructs the password from the unmodified single dicts at line i-1, so it
      # carries the whole password even for 20510 whose run word was cut (test.sh).

      line_nr = i - 1 if i > 1 else 1

      search_word = sed_line(dict1_lines, line_nr) + sed_line(dict2_lines, line_nr)

      matched = output_has_crack(r.mode, out, search_word, digest,
                                 r.pass_only, r.tmp) if rc == 0 else False

      classify(rc, matched, c)

    if i == max_i:
      break

  report(r.args, r.mode, "single", r.width, c, attack=6)


def a6_multi_params(mode):
  # test.sh attack_6 multi (test.sh).

  min_i, max_i = 1, 9

  if mode == 2500:
    max_i = 5
  elif mode == 3000:
    max_i = 8
  elif mode in (7700, 7701):
    max_i = 8
  elif mode == 8500:
    max_i = 8
  elif mode == 16800:
    max_i = 5
  elif mode == 22000:
    max_i = 5
  elif mode == 33500:
    min_i = 5
  elif mode == 33501:
    # The candidate is only a few characters once a multibyte byte is folded in, so a head of 8
    # would cover the whole word and leave the mask empty. Keep the head short enough that every
    # slot still has a tail for the mask.
    min_i = 5
  elif mode == 33502:
    min_i = 8
  elif mode == 37400:
    # pw_min 9: run only the longest slot (head 8 of the 9 bytes, one digit in the mask) so the
    # hybrid does not brute force a long run of digits over a slow DES hash.
    min_i = 8

  if is_timeout(mode):
    max_i = 5

    if mode == 3200:
      max_i = 3

  return min_i, max_i


def attack_6_multi(r):
  if has_multi_hash(r.mode):
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i = a6_multi_params(r.mode)
  optimized    = not r.args.pure

  hash_file = os.path.join(r.tmp, "m%05d_a6_hashes_multi.txt" % r.mode)
  dict1_mp  = os.path.join(r.tmp, "m%05d_a6_dict1_multi" % r.mode)

  i = 2

  while i < max_i:
    if i < min_i:
      i += 1

      continue

    pairs  = multi_pairs(r.mode, i, optimized)

    # a length outside the mode's password range has no passwords to test

    if len(pairs) == 0:
      i += 1

      continue

    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    write_hashes(hash_file, pairs, r.mode, r.file_only)
    write_dict(dict1_mp, d1)

    # The eight passwords of a length share one mask over the tail dict1 does not hold, spelled by
    # any of them since the length seeds their layout (test.sh).

    multi_model = pairs[0][0] if pairs else b""
    multi_head  = d1[0] if d1 else b""
    multi_tail  = multi_model[len(multi_head):]

    # When dict1 already holds the whole password the tail is empty, so there is nothing for the
    # mask to brute force. An empty mask drops the argument and hashcat faults with a usage error,
    # so skip the slot: it is not a valid -a 6 run at this length. This happens on the optimized
    # pass of a mode like 33501 whose short multibyte candidate leaves no byte past the dict head.
    if not multi_tail:
      i += 1

      continue

    mask = mask_literalize(mask_dots(len(multi_tail)), multi_tail)

    rc, out = run_hashcat(r.opts, r.mode, hash_file, None, attack=6,
                          extra=hybrid_extra([dict1_mp, mask]))

    matched = rc == 0

    if rc == 0:
      for j, (_, digest) in enumerate(pairs):
        if not output_has_crack(r.mode, out, sed_line(d1, j + 1) + sed_line(d2, j + 1),
                                digest, r.pass_only, r.tmp):
          matched = False

          break

    classify(rc, matched, c)

    i += 1

  report(r.args, r.mode, "multi", r.width, c, attack=6)


def attack_6(r):
  # test.sh attack_6: the wordlist plus a mask on the right. dict1 holds the head of the password
  # and the mask spells the tail, single hash then multi hash.

  if "single" in r.targets:
    attack_6_single(r)

  if "multi" in r.targets:
    attack_6_multi(r)


def a7_single_params(mode):
  # test.sh attack_7 single (test.sh). mask_offset drives the min == 0 custom split.

  min_i, max_i, mask_offset = 1, 8, 0

  if mode == 2500:
    max_i = 5
  elif mode == 14000:
    min_i, max_i, mask_offset = 0, 1, 4
  elif mode == 14100:
    min_i, max_i, mask_offset = 0, 1, 3
  elif mode == 14900:
    min_i, max_i, mask_offset = 0, 1, 5
  elif mode == 15400:
    min_i, max_i, mask_offset = 0, 1, 3
  elif mode == 16800:
    max_i = 5
  elif mode == 22000:
    max_i = 5

  return min_i, max_i, mask_offset


def attack_7_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i, mask_offset = a7_single_params(r.mode)
  optimized = not r.args.pure

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file  = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict2_base = os.path.join(r.tmp, "m%05d_a7_dict2" % r.mode)
  dict2_cust = os.path.join(r.tmp, "m%05d_a7_dict2_custom" % r.mode)

  write_dict(dict2_base, dict2_lines)

  # The min == 0 modes build a one line custom pair from the first password, split at mask_offset
  # (test.sh). The custom mask test.sh forms there is overwritten below, so only the dicts
  # matter. test.sh's earlier mask from the length-slot files, and the 2500/16800/22000 prefix
  # tweaks, are overwritten the same way and left out.

  custom_active = (min_i == 0)
  cust_d1       = None
  cust_d2       = None

  if custom_active:
    first   = sed_line(dict1_lines, 1) + sed_line(dict2_lines, 1)
    cust_d1 = [first[:mask_offset]]
    cust_d2 = [first[mask_offset:]]

    write_dict(dict2_cust, cust_d2)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1

    if i > min_i:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      line_nr = i - 1 if i > 1 else 1

      d1_lines = dict1_lines
      d2_lines = dict2_lines
      d2_path  = dict2_base
      active   = custom_active

      if r.mode == 20510:
        # PKZIP master key, 6 byte optimization: the kernel is fed the password with its first 6
        # bytes dropped and reconstructs them, so the candidate the mask and the dict build between
        # them has to be that stripped password, not the whole one. A short head spells the mask,
        # the rest trails in the dict; the head length follows the multi slot so the single and
        # multi runs line up, and is kept to at least 1 byte since an empty mask drops the argument
        # and the run faults.
        pass_full = sed_line(dict1_lines, line_nr) + sed_line(dict2_lines, line_nr)

        if len(pass_full) <= 6:
          continue

        cut        = pass_full[6:]
        mpairs     = multi_pairs(20510, i, optimized)
        md1, _     = build_multi_dicts(20510, i, mpairs)
        multi_head = md1[0] if md1 else b""
        mask_len   = len(mask_literalize(mask_dots(len(multi_head)), multi_head)) // 2

        if mask_len < 1:
          mask_len = 1

        if mask_len > len(cut):
          mask_len = len(cut)

        cust_d1 = [cut[:mask_len]]
        cust_d2 = [cut[mask_len:]]

        write_dict(dict2_cust, cust_d2)

        active = True

      # The custom dicts hold one line, built for this hash, so they are read at line 1, not at the
      # growing hash index line_nr.

      read_nr = line_nr

      if active:
        d1_lines = cust_d1
        d2_lines = cust_d2
        d2_path  = dict2_cust
        read_nr  = 1

      # -a 7 is mask plus dict, dict2 holds the tail, so the mask spells the head that dict1 holds.
      # It is built from what dict1 actually holds rather than from a fixed table, because a split
      # moved to a character boundary changes dict1's length (test.sh).

      dict1_line = sed_line(d1_lines, read_nr)
      mask       = mask_literalize(mask_dots(len(dict1_line)), dict1_line)

      rc, out = run_hashcat(r.opts, r.mode, target, None, attack=7,
                            extra=hybrid_extra([mask, d2_path]))

      search_word = sed_line(d1_lines, read_nr) + sed_line(d2_lines, read_nr)

      matched = output_has_crack(r.mode, out, search_word, digest,
                                 r.pass_only, r.tmp) if rc == 0 else False

      classify(rc, matched, c)

    if i == max_i:
      break

  report(r.args, r.mode, "single", r.width, c, attack=7)


def a7_multi_max(mode):
  # test.sh attack_7 multi (test.sh). 33500 sets a min the loop never reads, so only max
  # is carried here.

  max_i = 9

  if mode == 2500:
    max_i = 5
  elif mode == 3000:
    max_i = 8
  elif mode in (7700, 7701):
    max_i = 8
  elif mode == 8500:
    max_i = 8
  elif mode in (14000, 14100, 14900, 15400, 16800, 22000):
    max_i = 5
  elif mode in (33501, 33502):
    max_i = 3
  elif mode == 37400:
    # pw_min 9: keep the mask-on-the-left run to the shortest slot so the brute forced head stays a
    # few digits over a slow DES hash.
    max_i = 3

  if is_timeout(mode):
    max_i = 7

    if mode == 3200:
      max_i = 4

  return max_i


def attack_7_multi(r):
  if has_multi_hash(r.mode):
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  max_i     = a7_multi_max(r.mode)
  optimized = not r.args.pure

  hash_file  = os.path.join(r.tmp, "m%05d_a7_hashes_multi.txt" % r.mode)
  dict2_mp   = os.path.join(r.tmp, "m%05d_a7_dict2_multi" % r.mode)
  dict2_long = os.path.join(r.tmp, "m%05d_a7_dict2_multi_longer" % r.mode)

  i = 2

  while i < max_i:
    pairs  = multi_pairs(r.mode, i, optimized)

    # a length outside the mode's password range has no passwords to test

    if len(pairs) == 0:
      i += 1

      continue

    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    # The mask spells the head dict2 does not hold. 40001 and 40002 read it from a table instead,
    # but neither has a python oracle so neither is reached here (test.sh).

    multi_head = d1[0] if d1 else b""
    mask       = mask_literalize(mask_dots(len(multi_head)), multi_head)

    write_hashes(hash_file, pairs, r.mode, r.file_only)

    if r.file_only:
      # test.sh: a file based mode keeps the mask short by moving the rest of each
      # password into a dict of its own, since a mode like WPA has a minimum length of 8.
      mask_len   = len(mask) // 2
      long_lines = [(d1[j] + d2[j])[mask_len:] for j in range(len(pairs))]

      write_dict(dict2_long, long_lines)

      dict_file = dict2_long
    else:
      write_dict(dict2_mp, d2)

      dict_file = dict2_mp

    rc, out = run_hashcat(r.opts, r.mode, hash_file, None, attack=7,
                          extra=hybrid_extra([mask, dict_file]))

    matched = rc == 0

    if rc == 0:
      for j, (_, digest) in enumerate(pairs):
        if not output_has_crack(r.mode, out, sed_line(d1, j + 1) + sed_line(d2, j + 1),
                                digest, r.pass_only, r.tmp):
          matched = False

          break

    classify(rc, matched, c)

    i += 1

  report(r.args, r.mode, "multi", r.width, c, attack=7)


def attack_7(r):
  # test.sh attack_7: a mask on the left plus the wordlist. The mask spells the head of the password
  # and dict2 holds the tail, single hash then multi hash.

  if "single" in r.targets:
    attack_7_single(r)

  if "multi" in r.targets:
    attack_7_multi(r)


# -a 12 is both hybrids and more: the mask says where the dict word goes rather than the attack mode
# saying it, so one password is tried with the word in front of the mask, behind it, between two mask
# pieces, and with a ?w?q pair pulling a second word in behind the first. Its dicts are the single
# dict1 (split_for_combinator) with the run word appended, and its masks reuse the attack_3 helpers.
# The multi path builds the same length-slot dicts attack_6 and attack_7 do, so it reuses
# a6_multi_params, multi_pairs and build_multi_dicts.

# The modes attack_12 reports Skip for outright: a mode that accepts one candidate length only has
# nothing for a mask on both sides of the word to vary, and 20510 reports a plaintext that is not the
# candidate it was given. attack_6 and attack_7 already cover these (test.sh).

A12_SKIP = {14000, 14100, 14900, 15400, 20510}


def a12_single_max(mode):
  # test.sh attack_12 single (test.sh): the highest 1-based hash index a single run covers.

  if mode in (2500, 16800, 22000):
    return 6

  return 8


def report_skip_counts(r, target_name):
  # test.sh attack_12 forces the summary to Skip for an A12_SKIP mode while still printing the zeroed
  # counts line, not the reason form report_skip uses (test.sh). The loop breaks
  # before any candidate runs, so every count is zero.

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  print("%s > Skip : %d/%d not found, %d/%d not matched, %d/%d timeout, %d/%d skipped"
        % (context(r.args, r.mode, target_name, r.width, 12),
           c["nf"], c["cnt"], c["nm"], c["cnt"], c["to"], c["cnt"], c["rs"], c["cnt"]))


def attack_12_single(r):
  if r.mode in A12_SKIP:
    report_skip_counts(r, "single")

    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  max_i = a12_single_max(r.mode)

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict1_a12 = os.path.join(r.tmp, "m%05d_a12_dict1" % r.mode)
  dict2_a12 = os.path.join(r.tmp, "m%05d_a12_dict2" % r.mode)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1

    # test.sh: a slow mode stops after the sixth hash.
    if i > 6 and is_timeout(r.mode):
      break

    if i > 1:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      pass_len = len(word)

      # Some of the password becomes mask, the rest is the word. The mask is split between the two
      # sides of the word so the shape with a mask on both sides has something on both, and it is
      # capped at four characters because -a 12 uploads the mask rather than expanding it on the
      # device (test.sh).

      mask_len = i

      if mask_len > 4:
        mask_len = 4

      head_len = mask_len // 2
      word_len = pass_len - mask_len

      # test.sh: no room for a word means the hash is skipped and does not count.
      if word_len >= 1:
        head_end   = utf8_split_point(word, head_len)
        tail_start = utf8_split_point(word, head_len + word_len)

        mask_head = mask_literalize(mask_dots(head_end), word[:head_end])
        mask_tail = mask_literalize(mask_dots(pass_len - tail_start), word[tail_start:])

        for shape in ("first", "last", "middle", "q"):
          dicts = [dict1_a12]

          if shape == "first":
            word_end  = utf8_split_point(word, word_len)
            head_word = word[:word_end]
            mask      = b"?w" + mask_literalize(mask_dots(pass_len - word_end), word[word_end:])
          elif shape == "last":
            mask_start = utf8_split_point(word, mask_len)
            head_word  = word[mask_start:]
            mask       = mask_literalize(mask_dots(mask_start), word[:mask_start]) + b"?w"
          elif shape == "middle":
            head_word = word[head_end:tail_start]
            mask      = mask_head + b"?w" + mask_tail
          else:
            # The word itself is cut in two, so ?w and ?q each carry one half (test.sh).
            q_end = utf8_split_point(word, head_end + (tail_start - head_end) // 2)

            if q_end <= head_end or q_end >= tail_start:
              continue

            head_word = word[head_end:q_end]

            write_dict(dict2_a12, [word[q_end:tail_start]])

            mask  = mask_head + b"?w?q" + mask_tail
            dicts = [dict1_a12, dict2_a12]

          # dict1 with the run word appended, so hashcat finds it among others (test.sh).
          # test.sh shuffles the file here, which only reorders candidates it tries all of,
          # so the shuffle is left out.

          write_dict(dict1_a12, dict1_lines + [head_word])

          rc, out = run_hashcat(r.opts, r.mode, target, None, attack=12,
                                extra=hybrid_extra([mask] + dicts))

          matched = output_has_crack(r.mode, out, word, digest,
                                     r.pass_only, r.tmp) if rc == 0 else False

          classify(rc, matched, c)

    if i == max_i:
      break

  report(r.args, r.mode, "single", r.width, c, attack=12)


def attack_12_multi(r):
  if has_multi_hash(r.mode):
    return

  if r.mode in A12_SKIP:
    report_skip_counts(r, "multi")

    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  # test.sh's -a 12 multi window matches attack_6's exactly (test.sh vs 2587-2615).

  min_i, max_i = a6_multi_params(r.mode)
  optimized    = not r.args.pure

  hash_file = os.path.join(r.tmp, "m%05d_a12_hashes_multi.txt" % r.mode)
  dict1_mp  = os.path.join(r.tmp, "m%05d_a12_dict1_multi" % r.mode)
  dict2_mp  = os.path.join(r.tmp, "m%05d_a12_dict2_multi" % r.mode)

  i = 2

  while i < max_i:
    if i < min_i:
      i += 1

      continue

    pairs  = multi_pairs(r.mode, i, optimized)

    # a length outside the mode's password range has no passwords to test

    if len(pairs) == 0:
      i += 1

      continue

    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    write_hashes(hash_file, pairs, r.mode, r.file_only)
    write_dict(dict1_mp, d1)
    write_dict(dict2_mp, d2)

    # The two halves of the length let one shape put the word in front of the mask and the other
    # behind it, the tail and head dict1 and dict2 already hold (test.sh).

    multi_model = pairs[0][0] if pairs else b""
    multi_head  = d1[0] if d1 else b""
    multi_tail  = multi_model[len(multi_head):]

    for shape in ("first", "last"):
      if shape == "first":
        dict_file = dict1_mp
        mask      = b"?w" + mask_literalize(mask_dots(len(multi_tail)), multi_tail)
      else:
        dict_file = dict2_mp
        mask      = mask_literalize(mask_dots(len(multi_head)), multi_head) + b"?w"

      rc, out = run_hashcat(r.opts, r.mode, hash_file, None, attack=12,
                            extra=hybrid_extra([mask, dict_file]))

      matched = rc == 0

      if rc == 0:
        for j, (_, digest) in enumerate(pairs):
          if not output_has_crack(r.mode, out, sed_line(d1, j + 1) + sed_line(d2, j + 1),
                                  digest, r.pass_only, r.tmp):
            matched = False

            break

      classify(rc, matched, c)

    i += 1

  report(r.args, r.mode, "multi", r.width, c, attack=12)


def attack_12(r):
  # test.sh attack_12: the mask says where the dict word goes, so one password is tried with the word
  # before the mask, after it, between two mask pieces, and with a ?w?q pair, single then multi hash.

  if "single" in r.targets:
    attack_12_single(r)

  if "multi" in r.targets:
    attack_12_multi(r)


# One function per attack mode, each printing test.sh's summary lines for that attack. Every attack
# mode the old suite ran has an entry; a value outside this table is reported once on stderr.

ATTACKS = {
  0: attack_0,
  1: attack_1,
  3: attack_3,
  4: attack_4,
  6: attack_6,
  7: attack_7,
  8: attack_8,
  9: attack_9,
  12: attack_12,
}


# The self-test vector path (test.sh selftest_vector_read / selftest_vector_test /
# selftest_vector_sweep, plus the build_container_cmd and container_run_and_report parts they reach).
# It cracks a mode's own example hash, read out of the binary, so it needs no oracle and reaches a
# mode that has neither a .pm nor a .py. Every value here stays bytes until it is written to a file
# or handed to hashcat.


def sed_capture(info, pattern):
  # Mirror sed -n 's/.*<pattern>.*/\1/p' applied line by line, which is how selftest_vector_read
  # pulls a value out of the --machine-readable JSON (test.sh). The wrapping .* are greedy,
  # so the value is anchored on the key that follows it; only the one JSON line matches here.

  rx = re.compile(b".*" + pattern + b".*")

  out = []

  for line in info.split(b"\n"):
    m = rx.fullmatch(line)

    if m is not None:
      out.append(m.group(1))

  return b"\n".join(out)


def selftest_vector_read(mode):
  # test.sh selftest_vector_read (test.sh): read a mode's self-test vector out of hashcat with
  # --hash-info --machine-readable. The machine-readable form is the trustworthy one, since the
  # human-readable Example.Hash line is truncated past 200 characters. Returns
  # (hash, pass, format, deprecated) as bytes/str/bool, or None when the mode has no usable vector.

  # ISOLATION gives this read its own --session and cache, so -j workers reading vectors at the same
  # time do not collide on the default session files in ROOT and read back an empty result.
  proc = subprocess.run([BIN, "-m", str(mode), "--hash-info", "--machine-readable"] + ISOLATION,
                        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

  info = proc.stdout

  if info == b"":
    return None

  vhash = sed_capture(info, rb'"example_hash": "(.*)", "example_pass"')
  vpass = sed_capture(info, rb'"example_pass": "(.*)", "benchmark_mask"')
  vfmt  = sed_capture(info, rb'"example_hash_format": "([^"]*)"')

  # json_encode() escapes a backslash and a double quote, so undo that, in the same order test.sh
  # does: '\"' back to '"' first, then '\\' back to '\' (test.sh).

  vhash = vhash.replace(b'\\"', b'"').replace(b"\\\\", b"\\")

  deprecated = b'"is_deprecated": true' in info

  if vhash == b"" or vpass == b"":
    return None

  return (vhash, vpass, vfmt.decode("ascii", "replace"), deprecated)


def selftest_write_hash(mode, vhash, vfmt, path):
  # test.sh selftest_vector_test's hash-file write (test.sh). A binary-file mode is handed
  # its vector hex encoded, so it is decoded back to raw bytes; "N/A" has no hash to crack; every
  # other format is already the literal hash line. Returns True when a file was written.

  if "binary file only" in vfmt:
    with open(path, "wb") as fh:
      fh.write(bytes.fromhex(vhash.decode("ascii")))

    return True

  if vfmt == "N/A":
    return False

  with open(path, "wb") as fh:
    fh.write(vhash + b"\n")

  return True


def container_mask_from_password(pw, where):
  # test.sh container_mask_from_password (test.sh): the password with one digit given up as a
  # '?d', so the run has ten candidates rather than being handed the answer, every other byte staying
  # literal. 'first' or 'last' picks which digit; no digit means nothing to search, so hand the
  # password back as a literal mask.

  n = len(pw)

  order = range(0, n) if where == "first" else range(n - 1, -1, -1)

  for i in order:
    if b"0" <= pw[i:i + 1] <= b"9":
      return pw[:i] + b"?d" + pw[i + 1:]

  return pw


def build_container_extra(mode, attack, vpass, tmp):
  # test.sh build_container_cmd (test.sh), the branches the self-test path reaches. It returns
  # the argv that follows the hash for run_hashcat: a wordlist for -a 0, two dicts for -a 1, a mask
  # for -a 3, dict then mask for -a 6, mask then dict for -a 7. None for an attack it does not build.

  dict1 = os.path.join(tmp, "%d_cont_dict1" % mode)
  dict2 = os.path.join(tmp, "%d_cont_dict2" % mode)

  plen = len(vpass)

  if attack == 0:
    with open(dict1, "wb") as fh:
      fh.write(vpass + b"\n")

    return [dict1]

  if attack == 1:
    split = utf8_split_point(vpass, plen // 2)

    with open(dict1, "wb") as fh:
      fh.write(vpass[:split] + b"\n")

    with open(dict2, "wb") as fh:
      fh.write(vpass[split:] + b"\n")

    return [dict1, dict2]

  if attack == 3:
    return [container_mask_from_password(vpass, "last")]

  if attack == 6:
    split = utf8_split_point(vpass, plen - 1)

    with open(dict1, "wb") as fh:
      fh.write(vpass[:split] + b"\n")

    return [dict1, container_mask_from_password(vpass[split:], "last")]

  if attack == 7:
    split = utf8_split_point(vpass, 1)

    if split <= 0:
      split = 1

    with open(dict1, "wb") as fh:
      fh.write(vpass[split:] + b"\n")

    return [container_mask_from_password(vpass[:split], "first"), dict1]

  return None


# The container full-test families (test.sh truecrypt_test/veracrypt_test/luks_test/
# luks_legacy_test/luks2_test/cryptoloop_test). Their hash is a container file, not a generated
# string, so they have no .py oracle: the file (or a .hash extracted from it) is handed to hashcat
# as the hash, the password is CONTAINER_PASSWORD, and pass/fail is hashcat's exit code alone
# (selftest_status), with no hash:plain comparison. test.sh keeps these off the oracle pre-pass and
# branches on the family lists (test.sh); the same set is CONTAINER_MODES here.

CONTAINER_PASSWORD = b"hashcat"

# test.sh's fixed container masks (test.sh): TC and CL search the last letter, VeraCrypt the middle.
# The LUKS families instead build their mask from the password with container_mask_from_password.
CONTAINER_MASK     = "hashca?l"
CONTAINER_MASK_MID = "hashc?lt"

TC_TESTS_DIR    = os.path.join(TDIR, "tc_tests")
VC_TESTS_DIR    = os.path.join(TDIR, "vc_tests")
LUKS_TESTS_DIR  = os.path.join(TDIR, "luks_tests")
LUKS2_TESTS_DIR = os.path.join(TDIR, "luks2_tests")
CL_TESTS_DIR    = os.path.join(TDIR, "cl_tests")


def container_attack(args):
  # test.sh runs the container families with ${ATTACK} (default 0); -a all becomes -a 3, since
  # 0,1,3,6,7 over every container file would take far too long (test.sh luks2_test et al.).
  if args.attack == "all":
    return 3

  return int(args.attack)


def container_extract(tool, container, hash_file, extra_args=()):
  # Run one of the tools/*2hashcat.py extractors and capture the hash it prints into hash_file, the
  # way test.sh does with `eval "...2hashcat.py" "<container>" > <hashfile>`. Returns True on success.
  proc = subprocess.run([sys.executable, os.path.join(TDIR, tool), container] + list(extra_args),
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

  if proc.returncode != 0 or not proc.stdout:
    return False

  with open(hash_file, "wb") as fh:
    fh.write(proc.stdout)

  return True


def container_report(args, mode, attack, width, label, e):
  # test.sh's per-mode container line, with the family's extra field spliced in before the closing
  # bracket (e.g. ", LUKS2-mode <img>"). Pass/fail follows selftest_verdict, the exit-code buckets.
  ctx = context(args, mode, "single", width, attack)
  ctx = ctx[:-2] + ", %s ]" % label

  v = selftest_verdict(e)

  print("%s > %s : %d/1 not found, %d/1 not matched, %d/1 timeout, %d/1 skipped"
        % (ctx, v, e["nf"], e["nm"], e["to"], e["rs"]))

  note_verdict(v)


def container_crack(args, opts, mode, attack, hash_file, width, label, extra, crack_mode=None,
                    report_attack=None):
  # One container crack: run hashcat with the given trailing argv (a wordlist/mask), then print the
  # test.sh-style line. Pass/fail is the exit code alone. crack_mode lets the CL family crack under
  # the generic -m 14500 while the line still reports the mode selected; report_attack lets VeraCrypt
  # print "Attack 0" while running -a 3, the cosmetic label test.sh happens to use (test.sh).
  if extra is None:
    return None

  rc, _ = run_hashcat(opts + ["--backend-vector-width", str(width)], crack_mode or mode, hash_file,
                      None, attack=attack, extra=list(extra))
  e = selftest_status(rc)

  container_report(args, mode, attack if report_attack is None else report_attack, width, label, e)

  return e


def container_luks2(args, mode, attack, width, tmp):
  # test.sh luks2_test (test.sh): extract every *.img in luks2_tests with luks2hashcat.py and crack
  # the resulting hash under -m 34100.
  opts = base_opts(args)

  imgs = sorted(f for f in os.listdir(LUKS2_TESTS_DIR)
                if f.endswith(".img")) if os.path.isdir(LUKS2_TESTS_DIR) else []

  if not imgs:
    report_skip(args, mode, "single", width, "luks2 test files are missing", attack)
    return

  for img in imgs:
    hash_file = os.path.join(tmp, img + ".hash")

    if not container_extract("luks2hashcat.py", os.path.join(LUKS2_TESTS_DIR, img), hash_file):
      report_skip(args, mode, "single", width, "could not extract %s" % img, attack)
      continue

    extra = build_container_extra(mode, attack, CONTAINER_PASSWORD, tmp)
    container_crack(args, opts, mode, attack, hash_file, width, "LUKS2-mode %s" % img[:-4], extra)


# test.sh luks_test's per-mode hash+cipher (test.sh): 29511+ each map to one hash+cipher and vary
# only the cipher mode and key size.
LUKS1_HASH_CIPHER = {
  29511: ("sha1", "aes"),      29512: ("sha1", "serpent"),      29513: ("sha1", "twofish"),
  29521: ("sha256", "aes"),    29522: ("sha256", "serpent"),    29523: ("sha256", "twofish"),
  29531: ("sha512", "aes"),    29532: ("sha512", "serpent"),    29533: ("sha512", "twofish"),
  29541: ("ripemd160", "aes"), 29542: ("ripemd160", "serpent"), 29543: ("ripemd160", "twofish"),
}


def luks_variants():
  # test.sh's luksMode x luksKeySize double loop with the keysize->mode validity filter (test.sh):
  # 128 is cbc only, 512 is xts only, 256 is any.
  for lmode in ("cbc-essiv", "cbc-plain64", "xts-plain64"):
    for ksize in ("128", "256", "512"):
      if ksize == "128" and lmode == "xts-plain64":
        continue

      if ksize == "512" and lmode != "xts-plain64":
        continue

      yield lmode, ksize


def container_luks1(args, mode, attack, width, tmp):
  # test.sh luks_test (test.sh): for this mode's hash+cipher, extract each valid .luks with
  # luks2hashcat.py and crack the hash under -m <mode>.
  luks_hash, luks_cipher = LUKS1_HASH_CIPHER[mode]
  opts = base_opts(args)

  for lmode, ksize in luks_variants():
    name      = "hashcat_%s_%s_%s_%s" % (luks_hash, luks_cipher, lmode, ksize)
    container = os.path.join(LUKS_TESTS_DIR, name + ".luks")
    label     = "Luks-Mode %s-%s-%s-%s" % (luks_hash, luks_cipher, lmode, ksize)

    if not os.path.isfile(container):
      continue

    hash_file = os.path.join(tmp, name + ".hash")

    if not container_extract("luks2hashcat.py", container, hash_file):
      report_skip(args, mode, "single", width, "could not extract %s" % name, attack)
      continue

    extra = build_container_extra(mode, attack, CONTAINER_PASSWORD, tmp)
    container_crack(args, opts, mode, attack, hash_file, width, label, extra)


def container_luks_legacy(args, mode, attack, width, tmp):
  # test.sh luks_legacy_test (test.sh): 14600 accepts every hash+cipher, and takes the .luks file
  # directly, with no luks2hashcat.py extraction. That direct-file handling is the 14600-vs-29511+
  # difference.
  opts = base_opts(args)

  for luks_hash in ("sha1", "sha256", "sha512", "ripemd160"):
    for luks_cipher in ("aes", "serpent", "twofish"):
      for lmode, ksize in luks_variants():
        name      = "hashcat_%s_%s_%s_%s" % (luks_hash, luks_cipher, lmode, ksize)
        container = os.path.join(LUKS_TESTS_DIR, name + ".luks")
        label     = "luksMode %s-%s-%s-%s" % (luks_hash, luks_cipher, lmode, ksize)

        if not os.path.isfile(container):
          continue

        extra = build_container_extra(mode, attack, CONTAINER_PASSWORD, tmp)
        container_crack(args, opts, mode, attack, container, width, label, extra)


# TrueCrypt (62xx and 293xx). Like VeraCrypt below, the family ports as data rather than a case
# table: the mode's tens digit is the hash and the ones digit is the XTS key size, which is the
# number of cascaded ciphers (1, 2 or 3). Every tc_tests container that matches the hash, the cascade
# depth and the boot flag is tested. hash digit 4 is RIPEMD160 in boot mode, as test.sh had it.
TC_HASH_DIGIT  = {1: "ripemd160", 2: "sha512", 3: "whirlpool", 4: "ripemd160"}
TC_BOOT_DIGITS = {4}
TC_MODES = {base + h * 10 + k for base in (6200, 29300) for h in (1, 2, 3, 4) for k in (1, 2, 3)}


def container_truecrypt(args, mode, width, tmp):
  # test.sh truecrypt_test (test.sh): 62xx pass the .tc container directly, 293xx extract it first
  # with truecrypt2hashcat.py; always -a 3 with CONTAINER_MASK. The line's field is "tcMode <n>".
  opts = base_opts(args)

  s    = "%05d" % mode
  hfun = TC_HASH_DIGIT.get(int(s[-2]))
  boot = int(s[-2]) in TC_BOOT_DIGITS
  ncip = int(s[-1])

  if hfun is None or ncip not in (1, 2, 3):
    return

  prefix  = "hashcat_%s_" % hfun
  tc_mode = 0

  for fname in sorted(os.listdir(TC_TESTS_DIR)):
    if not fname.startswith(prefix) or not fname.endswith(".tc"):
      continue

    combo = fname[len(prefix):-len(".tc")]

    if boot != combo.endswith("_boot"):
      continue

    if boot:
      combo = combo[:-len("_boot")]

    if combo.count("-") != ncip - 1:
      continue

    container = os.path.join(TC_TESTS_DIR, fname)

    if mode < 29300:
      hash_arg = container
    else:
      hash_arg = os.path.join(tmp, fname + ".hash")

      if not container_extract("truecrypt2hashcat.py", container, hash_arg):
        report_skip(args, mode, "single", width, "could not extract %s" % fname, 3)
        continue

    container_crack(args, opts, mode, 3, hash_arg, width, "tcMode %d" % tc_mode, [CONTAINER_MASK])
    tc_mode += 1


# test.sh veracrypt_test (test.sh) derives the container name from the mode digits rather than a
# case table, so the whole family ports as data. hash_digit = mode[3], cipher_digit = mode[4].
VC_HASH_DIGIT  = {1: "ripemd160", 2: "sha512", 3: "whirlpool", 4: "ripemd160",
                  5: "sha256", 6: "sha256", 7: "streebog", 8: "streebog",
                  9: "blake2s"}
VC_BOOT_DIGITS = {4, 6, 8}
VC_CASCADES    = {
  1: {0: "aes", 1: "serpent", 2: "twofish", 3: "camellia", 5: "kuznyechik"},
  2: {0: "aes-twofish", 1: "serpent-aes", 2: "twofish-serpent", 3: "camellia-kuznyechik",
      4: "camellia-serpent", 5: "kuznyechik-aes", 6: "kuznyechik-twofish"},
  3: {0: "aes-twofish-serpent", 1: "serpent-twofish-aes", 5: "kuznyechik-serpent-camellia"},
}

VC_MODES = {13711, 13712, 13713, 13721, 13722, 13723, 13731, 13732, 13733, 13741, 13742, 13743,
            13751, 13752, 13753, 13761, 13762, 13763, 13771, 13772, 13773, 13781, 13782, 13783,
            29411, 29412, 29413, 29421, 29422, 29423, 29431, 29432, 29433, 29441, 29442, 29443,
            29451, 29452, 29453, 29461, 29462, 29463, 29471, 29472, 29473, 29481, 29482, 29483,
            29491, 29492, 29493}


def container_veracrypt(args, mode, width, tmp):
  # test.sh veracrypt_test (test.sh): 137xx pass the .vc directly, 294xx extract with
  # veracrypt2hashcat.py; always -a 3 with CONTAINER_MASK_MID. A _pim<N> container adds the PIM
  # options. Invalid hash+cipher pairs have no file and are skipped, as test.sh does.
  opts = base_opts(args)

  s = "%05d" % mode
  hfun = VC_HASH_DIGIT.get(int(s[3]))

  if hfun is None:
    return

  boot     = "_boot" if int(s[3]) in VC_BOOT_DIGITS else ""
  cascades = VC_CASCADES.get(int(s[4]), {})

  for variation in range(7):
    cascade = cascades.get(variation)

    if cascade is None:
      continue

    base     = "hashcat_%s_%s%s" % (hfun, cascade, boot)
    filename = os.path.join(VC_TESTS_DIR, base + ".vc")
    pim_opts = []

    if not os.path.isfile(filename):
      match = None

      for cand in sorted(glob.glob(os.path.join(VC_TESTS_DIR, base + "_pim*.vc"))):
        pim = cand[len(os.path.join(VC_TESTS_DIR, base)) + 4:-3]

        if pim.isdigit():
          match = (cand, pim)
          break

      if match is None:
        continue

      filename, pim = match
      pim_opts = ["--veracrypt-pim-start", pim, "--veracrypt-pim-stop", pim]

    if mode < 29400:
      hash_arg = filename
    else:
      hash_arg = os.path.join(tmp, base + ".hash")

      if not container_extract("veracrypt2hashcat.py", filename, hash_arg):
        report_skip(args, mode, "single", width, "could not extract %s" % base, 3)
        continue

    container_crack(args, opts + pim_opts, mode, 3, hash_arg, width, "Cipher %s" % cascade,
                    [CONTAINER_MASK_MID], report_attack=0)


# test.sh cryptoloop_test (test.sh): 145HC, H the hash digit and C the cipher digit; every mode is
# cracked under -m 14500 after extraction with cryptoloop2hashcat.py, over key sizes 128/192/256.
CL_HASH_DIGIT   = {1: "sha1", 2: "sha256", 3: "sha512", 4: "ripemd160", 5: "whirlpool"}
CL_CIPHER_DIGIT = {1: "aes", 2: "serpent", 3: "twofish"}

CL_MODES = {14511, 14512, 14513, 14521, 14522, 14523, 14531, 14532, 14533,
            14541, 14542, 14543, 14551, 14552, 14553}


def container_cryptoloop(args, mode, width, tmp):
  opts = base_opts(args)

  s      = "%05d" % mode
  hfun   = CL_HASH_DIGIT.get(int(s[3]))
  cipher = CL_CIPHER_DIGIT.get(int(s[4]))

  if hfun is None or cipher is None:
    return

  for ksize in ("128", "192", "256"):
    img = os.path.join(CL_TESTS_DIR, "hashcat_%s_%s_%s.img" % (hfun, cipher, ksize))

    if not os.path.isfile(img):
      continue

    hash_arg = os.path.join(tmp, "hashcat_%s_%s_%s.hash" % (hfun, cipher, ksize))

    proc = subprocess.run([sys.executable, os.path.join(TDIR, "cryptoloop2hashcat.py"),
                           "--source", img, "--hash", hfun, "--cipher", cipher, "--keysize", ksize],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    if proc.returncode != 0 or not proc.stdout:
      report_skip(args, mode, "single", width, "could not extract %s" % os.path.basename(img), 3)
      continue

    with open(hash_arg, "wb") as fh:
      fh.write(proc.stdout)

    # test.sh always cracks the CL family under the generic mode 14500, but reports the mode selected.
    container_crack(args, opts, mode, 3, hash_arg, width, "Key-Size %s" % ksize, [CONTAINER_MASK],
                    crack_mode=14500)


def run_container_mode(args, mode, tmp):
  # Dispatch a container mode to its family test, once per requested vector width (test.sh runs the
  # container families inside its per-width loop).
  attack = container_attack(args)

  for width in widths_for(args.vector):
    if mode == 34100:
      container_luks2(args, mode, attack, width, tmp)
    elif mode == 14600:
      container_luks_legacy(args, mode, attack, width, tmp)
    elif mode in LUKS1_HASH_CIPHER:
      container_luks1(args, mode, attack, width, tmp)
    elif mode in TC_MODES:
      container_truecrypt(args, mode, width, tmp)
    elif mode in VC_MODES:
      container_veracrypt(args, mode, width, tmp)
    elif mode in CL_MODES:
      container_cryptoloop(args, mode, width, tmp)


# -g (--generate): the real-container generation path, the port of test.sh's -g. Instead of reading
# the containers shipped in the tree or fetched from hashcat.net, -g builds a fresh one with the tool
# that owns each format and cracks that, so the whole path is tested end to end against a real
# artifact. It is an addition to the oracle for the archive families, and it replaces the shipped read
# for the container families (their dirs are repointed at a directory this run fills). CryptoLoop and
# 14600 have no generator, so they are not in GEN_MODES: -g does not cover them.

GPG_GEN_MODES      = {17010, 17020, 17030, 17040, 17050}
PKZIP_GEN_MODES    = {17200, 17210, 17220, 17225, 17230}
RAR_GEN_MODES      = {12500, 13000, 23700, 23800}
SEVENZIP_GEN_MODES = {11600, 13600}
PDF_GEN_MODES      = {10400, 10500, 10700}
SSH_GEN_MODES      = {22931}

ARCHIVE_GEN_MODES = (GPG_GEN_MODES | PKZIP_GEN_MODES | RAR_GEN_MODES | SEVENZIP_GEN_MODES
                     | PDF_GEN_MODES | SSH_GEN_MODES)

# The container families -g can build. 14600 (legacy LUKS) and the CryptoLoop modes have no generator.
CONTAINER_GEN_MODES = ({34100} | set(LUKS1_HASH_CIPHER) | TC_MODES | VC_MODES)

GEN_MODES = ARCHIVE_GEN_MODES | CONTAINER_GEN_MODES

# Of those, the families whose generator needs root: the LUKS payload has to be a real filesystem,
# which is device-mapper, and tcplay insists on a block device. Everything else builds as the user.
GEN_SUDO_MODES = ({34100} | set(LUKS1_HASH_CIPHER) | TC_MODES)

# A generated container is built with a password from the same generator the oracles use (test.sh
# container_password), so it carries whatever bytes that draws rather than a baked-in 'hashcat' that a
# test could pass on by accident. An optimized run builds ASCII, because the optimized kernels cannot
# match a multi byte password against a real artifact. These globals are the shipped-container
# defaults; main() reassigns them under -g.
GEN_LOCALE = os.environ.get("UTF8_LOCALE", "C.UTF-8")

# Runs that did not run in full: a missing tool, a combination the tool refuses, or an extractor that
# produced nothing. test.sh keeps these in one list and prints them at the end (record_skip/note/
# error, print_skip_summary), because a container test that silently did not run reads like a pass.
GEN_SKIPS = []


def gen_record(mode, kind, reason):
  GEN_SKIPS.append((mode, kind, reason))
  print("[ test.py ] [ Type %d ] > %s : %s" % (mode, kind, reason))


def gen_skip(mode, reason):
  gen_record(mode, "Skip", reason)


def gen_note(mode, reason):
  gen_record(mode, "Note", reason)


def gen_error(mode, reason):
  # An Error is a real failure, not a tool that is merely absent: an extractor that produced no hash
  # for a container it was handed, say. Count it as a failing verdict here, not in gen_record, so a
  # -g run that generated nothing exits non-zero while gen_skip and gen_note (a missing tool, a note)
  # stay out of the tally.
  note_verdict("Error")
  gen_record(mode, "Error", reason)


def print_gen_summary():
  if not GEN_SKIPS:
    return

  seen   = set()
  unique = []

  for item in GEN_SKIPS:
    if item not in seen:
      seen.add(item)
      unique.append(item)

  print()
  print("[ test.py ] > %d test(s) did not run in full:" % len(unique))

  for mode, kind, reason in unique:
    print("[ test.py ] [ Type %d ] > %s : %s" % (mode, kind, reason))

  print()


def gen_env():
  # test.sh runs every generator under a UTF-8 locale so a multi byte password reaches the tool as the
  # characters it is rather than as mojibake.
  e = dict(os.environ)
  e["LC_ALL"] = GEN_LOCALE
  e["LANG"]   = GEN_LOCALE

  return e


def gen_run(cmd, stdin=None, sudo=False):
  # Run one generation tool quietly. sudo prepends "sudo -n": main() authenticates and keeps the
  # ticket warm up front, so a generator never stops for a password partway through a long run.
  if sudo:
    cmd = ["sudo", "-n"] + cmd

  proc = subprocess.run(cmd, input=stdin, env=gen_env(),
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  return proc.returncode, proc.stdout


def gen_password_string():
  # The password the containers are built with (test.sh container_password): 12 bytes from
  # test_module_runner.py for mode 0, ASCII under an optimized run. Returned as text for a tool's argv.
  env = dict(os.environ)

  if not GEN_PURE:
    env["NO_NON_ASCII"] = "1"

  proc = subprocess.run([sys.executable, RUNNER, "password", "0", "12"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)

  return proc.stdout.rstrip(b"\n")


# GEN_PURE mirrors "is this a pure-kernel run": it decides whether generated passwords may carry
# non-ASCII. Set in main() from args.pure before gen_password_string() runs.
GEN_PURE = False


def _tool(env_name, name):
  # A generator tool: the env override, else PATH, else John's default run directory, else the bare
  # name so command lookup fails with a message that includes it.
  override = os.environ.get(env_name)

  if override:
    return override

  found = shutil.which(name)

  if found:
    return found

  cand = os.path.join(os.path.expanduser("~"), "john", "run", name)

  return cand if os.path.exists(cand) else name


def _have(path):
  return shutil.which(path) is not None or os.path.exists(path)


def _john_extract(raw, token_re):
  # test.sh's `<tool> ... | sed 's/^[^:]*://' | grep -oE '<token>' | head -1`: the first token that
  # matches, from a John extractor's output. The tools prepend "name:", and every hash token here uses
  # '*' or '$' rather than ':' internally, so searching each whole line for the token is equivalent.
  for line in raw.decode("utf-8", "replace").splitlines():
    m = re.search(token_re, line)

    if m:
      return m.group(0)

  return None


def write_hash(hash_file, token):
  with open(hash_file, "w") as fh:
    fh.write(token + "\n")


def archive_attacks(args, fast):
  # test.sh runs a fast archive mode (PKZIP) over 0/1/3 to cover its per-attack kernels when -a is
  # "all", and a slow one over a0 only. A named -a runs just that one, if it is one -g can build.
  if args.attack == "all":
    return [0, 1, 3] if fast else [0]

  a = int(args.attack)

  return [a] if a in (0, 1, 3, 6, 7) else []


def archive_crack(args, mode, hash_file, label, tmp, fast):
  # Crack a generated archive/key over the requested attacks and vector widths, the test.sh-style line
  # per run (build_container_cmd + container_run_and_report). The password is the one it was built
  # with, in CONTAINER_PASSWORD.
  opts = base_opts(args)

  for attack in archive_attacks(args, fast):
    extra = build_container_extra(mode, attack, CONTAINER_PASSWORD, tmp)

    if extra is None:
      continue

    for width in widths_for(args.vector):
      container_crack(args, opts, mode, attack, hash_file, width, label, extra)


# ---- container generators (test.sh veracrypt_generate/truecrypt_generate/luks*_generate) ----

def vc_encryption_name(cascade):
  # test.sh spells a cascade "aes-twofish-serpent"; veracrypt wants "AES(Twofish(Serpent))".
  names = {"aes": "AES", "serpent": "Serpent", "twofish": "Twofish",
           "camellia": "Camellia", "kuznyechik": "Kuznyechik"}

  out   = ""
  close = ""

  for part in cascade.split("-"):
    if part not in names:
      return None

    if not out:
      out = names[part]
    else:
      out   = "%s(%s" % (out, names[part])
      close += ")"

  return out + close


def veracrypt_generate(mode, vc_hash, cascade, out_file):
  # test.sh veracrypt_generate: build the volume with the veracrypt console binary, as the user. 1.26
  # dropped RIPEMD-160 for new volumes, so those need VERACRYPT_BIN pointed at a 1.25.9 or older build.
  vbin = os.environ.get("VERACRYPT_BIN", "veracrypt")

  if not _have(vbin):
    gen_skip(mode, "veracrypt not found, so no VeraCrypt volume can be generated (set VERACRYPT_BIN=/path/to/veracrypt)")
    return False

  encryption = vc_encryption_name(cascade)

  if encryption is None:
    gen_skip(mode, "no veracrypt name for cipher cascade %s" % cascade)
    return False

  if os.path.exists(out_file):
    os.remove(out_file)

  # 1 MiB is over VeraCrypt's minimum and keeps generation to a moment; hashcat only reads the header.
  gen_run([vbin, "--text", "--create", out_file, "--size=1M",
           "--password=%s" % CONTAINER_PASSWORD.decode("utf-8"), "--volume-type=normal",
           "--encryption=%s" % encryption, "--hash=%s" % vc_hash, "--filesystem=none",
           "--pim=0", "--keyfiles=", "--random-source=/dev/urandom", "--non-interactive"])

  if not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
    if os.path.exists(out_file):
      os.remove(out_file)

    if vc_hash == "ripemd160":
      gen_skip(mode, "%s will not create RIPEMD-160 volumes; 1.26 dropped them, so point VERACRYPT_BIN "
                     "at a 1.25.9 or older build to cover these" % vbin)
    else:
      gen_skip(mode, "veracrypt refused %s + %s, which is not a combination it supports" % (vc_hash, encryption))

    return False

  return True


TC_PRF_NAME    = {"ripemd160": "RIPEMD160", "sha512": "SHA512", "whirlpool": "whirlpool"}
TC_CIPHER_SPEC = {
  "aes": "AES-256-XTS", "serpent": "SERPENT-256-XTS", "twofish": "TWOFISH-256-XTS",
  "aes-twofish": "TWOFISH-256-XTS,AES-256-XTS", "serpent-aes": "AES-256-XTS,SERPENT-256-XTS",
  "twofish-serpent": "SERPENT-256-XTS,TWOFISH-256-XTS",
  "aes-twofish-serpent": "SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS",
  "serpent-twofish-aes": "AES-256-XTS,TWOFISH-256-XTS,SERPENT-256-XTS",
}

# test.sh truecrypt_container_name (test.sh): the cascade for a given cipher count and tcMode.
TC_CASCADE_BY_COUNT = {
  1: {0: "aes", 1: "serpent", 2: "twofish"},
  2: {0: "aes-twofish", 1: "serpent-aes", 2: "twofish-serpent"},
  3: {0: "aes-twofish-serpent", 1: "serpent-twofish-aes"},
}


def truecrypt_generate(mode, prf, cascade, out_file, tmp):
  # test.sh truecrypt_generate: tcplay is the only creator left for the format, and it needs a block
  # device, so a loop device and sudo, and it reads its passphrase from a terminal, so expect.
  tcplay = _tool("TCPLAY_BIN", "tcplay")

  if not _have(tcplay):
    gen_skip(mode, "tcplay not found, so no TrueCrypt volume can be generated (apt install tcplay, or set TCPLAY_BIN=...)")
    return False

  if not shutil.which("expect"):
    gen_skip(mode, "expect not found, and tcplay reads its passphrase from a terminal (apt install expect)")
    return False

  prf_name = TC_PRF_NAME.get(prf)
  cipher   = TC_CIPHER_SPEC.get(cascade)

  if prf_name is None or cipher is None:
    gen_skip(mode, "tcplay has no PBKDF PRF/cipher chain for %s + %s" % (prf, cascade))
    return False

  exp = os.path.join(tmp, "tcplay_create.exp")

  with open(exp, "w") as fh:
    fh.write("set timeout 600\n"
             "set dev  [lindex $argv 0]\n"
             "set pass [lindex $argv 1]\n"
             "set prf  [lindex $argv 2]\n"
             "set ciph [lindex $argv 3]\n"
             "set bin  [lindex $argv 4]\n"
             "spawn $bin --create --device=$dev --cipher=$ciph --pbkdf-prf=$prf --insecure-erase --weak-keys\n"
             'expect "Passphrase:"        { send "$pass\\r" }\n'
             'expect "Repeat passphrase:" { send "$pass\\r" }\n'
             'expect "(y/n)"              { send "y\\r" }\n'
             "expect eof\n"
             "catch wait result\n"
             "exit [lindex $result 3]\n")

  if os.path.exists(out_file):
    os.remove(out_file)

  # tcplay writes only the header, which is all hashcat reads, but it insists on a block device.
  with open(out_file, "wb") as fh:
    fh.truncate(2 * 1024 * 1024)

  rc, out = gen_run(["losetup", "--show", "-f", out_file], sudo=True)
  loop    = out.decode("utf-8", "replace").strip()

  if rc != 0 or not loop:
    os.remove(out_file)
    gen_skip(mode, "could not attach a loop device, which tcplay needs (sudo losetup)")
    return False

  rc, _ = gen_run(["expect", exp, loop, CONTAINER_PASSWORD.decode("utf-8"), prf_name, cipher, tcplay], sudo=True)

  gen_run(["losetup", "-d", loop], sudo=True)

  if rc != 0 or os.path.getsize(out_file) == 0:
    os.remove(out_file)
    gen_skip(mode, "tcplay could not create a %s + %s volume" % (prf, cascade))
    return False

  return True


def _luks_chain(lmode):
  # cbc-essiv is written cbc-essiv:sha256 in a cryptsetup cipher spec.
  return "cbc-essiv:sha256" if lmode == "cbc-essiv" else lmode


def luks1_generate(mode, luks_hash, luks_cipher, lmode, ksize, out_file):
  # test.sh luks1_generate: cryptsetup writes the header as the user, but hashcat verifies a LUKS
  # candidate by decrypting the payload and recognizing a filesystem, so the volume has to be opened
  # and formatted, and that is device-mapper, which needs root.
  cryptsetup = _tool("CRYPTSETUP_BIN", "cryptsetup")

  if not _have(cryptsetup):
    gen_skip(mode, "cryptsetup not found, so no LUKS1 container can be generated")
    return False

  chain = _luks_chain(lmode)
  name  = "luksgen%d_%s" % (os.getpid(), ksize)

  if os.path.exists(out_file):
    os.remove(out_file)

  with open(out_file, "wb") as fh:
    fh.truncate(20 * 1024 * 1024)

  # 1000 is cryptsetup's floor: the point is to test the format, not to wait for a realistic KDF.
  rc, _ = gen_run([cryptsetup, "luksFormat", "--batch-mode", "--type", "luks1",
                   "--cipher", "%s-%s" % (luks_cipher, chain), "--key-size", ksize,
                   "--hash", luks_hash, "--pbkdf-force-iterations", "1000", out_file],
                  stdin=CONTAINER_PASSWORD + b"\n", sudo=True)

  if rc != 0:
    os.remove(out_file)
    gen_skip(mode, "cryptsetup refused %s + %s-%s at %s bits" % (luks_hash, luks_cipher, chain, ksize))
    return False

  rc, _ = gen_run([cryptsetup, "open", out_file, name], stdin=CONTAINER_PASSWORD + b"\n", sudo=True)

  if rc != 0:
    os.remove(out_file)
    gen_skip(mode, "could not open the generated %s + %s-%s container (device-mapper needs sudo)"
             % (luks_hash, luks_cipher, chain))
    return False

  gen_run(["mkfs.ext4", "-q", "/dev/mapper/%s" % name], sudo=True)
  gen_run([cryptsetup, "close", name], sudo=True)

  if os.path.getsize(out_file) == 0:
    gen_skip(mode, "the generated %s + %s-%s container came out empty" % (luks_hash, luks_cipher, chain))
    return False

  return True


def luks2_generate(mode, lmode, ksize, out_file):
  # test.sh luks2_generate: the smallest argon2id 34100 is still itself at (t=4, m=16 MiB, p=1), the
  # shape of the container hashcat.net ships. Opening and formatting the payload needs root, as LUKS1.
  cryptsetup = _tool("CRYPTSETUP_BIN", "cryptsetup")

  if not _have(cryptsetup):
    gen_skip(mode, "cryptsetup not found, so no LUKS2 container can be generated")
    return False

  chain = _luks_chain(lmode)
  name  = "luks2gen%d_%s" % (os.getpid(), ksize)

  if os.path.exists(out_file):
    os.remove(out_file)

  # LUKS2 keeps a 16 MiB metadata area, so the file has to be larger than a LUKS1 one for a filesystem.
  with open(out_file, "wb") as fh:
    fh.truncate(48 * 1024 * 1024)

  rc, _ = gen_run([cryptsetup, "luksFormat", "--batch-mode", "--type", "luks2",
                   "--cipher", "aes-%s" % chain, "--key-size", ksize, "--hash", "sha256",
                   "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
                   "--pbkdf-memory", "16384", "--pbkdf-parallel", "1", out_file],
                  stdin=CONTAINER_PASSWORD + b"\n", sudo=True)

  if rc != 0:
    os.remove(out_file)
    gen_skip(mode, "cryptsetup refused aes-%s at %s bits for LUKS2" % (chain, ksize))
    return False

  rc, _ = gen_run([cryptsetup, "open", out_file, name], stdin=CONTAINER_PASSWORD + b"\n", sudo=True)

  if rc != 0:
    os.remove(out_file)
    gen_skip(mode, "could not open the generated aes-%s LUKS2 container (device-mapper needs sudo)" % chain)
    return False

  gen_run(["mkfs.ext4", "-q", "/dev/mapper/%s" % name], sudo=True)
  gen_run([cryptsetup, "close", name], sudo=True)

  if os.path.getsize(out_file) == 0:
    gen_skip(mode, "the generated aes-%s LUKS2 container came out empty" % chain)
    return False

  return True


def generate_containers(args, mode, tmp):
  # Fill this mode's family with fresh containers, into the *_TESTS_DIR the container read path then
  # walks (main() has repointed those at a per-run directory). test.sh's -g branches inside each
  # *_test function; the same generation, one step ahead of the same read.
  if mode == 34100:
    os.makedirs(LUKS2_TESTS_DIR, exist_ok=True)

    for lmode, ksize in luks_variants():
      out = os.path.join(LUKS2_TESTS_DIR, "luks2-aes-argon2id-t4-m16-p1-%s-%s.img" % (lmode, ksize))

      if not os.path.exists(out):
        luks2_generate(mode, lmode, ksize, out)

    return

  if mode in LUKS1_HASH_CIPHER:
    os.makedirs(LUKS_TESTS_DIR, exist_ok=True)
    luks_hash, luks_cipher = LUKS1_HASH_CIPHER[mode]

    for lmode, ksize in luks_variants():
      name = "hashcat_%s_%s_%s_%s" % (luks_hash, luks_cipher, lmode, ksize)
      out  = os.path.join(LUKS_TESTS_DIR, name + ".luks")

      if not os.path.exists(out):
        luks1_generate(mode, luks_hash, luks_cipher, lmode, ksize, out)

    return

  if mode in TC_MODES:
    os.makedirs(TC_TESTS_DIR, exist_ok=True)

    s    = "%05d" % mode
    hfun = TC_HASH_DIGIT.get(int(s[-2]))
    boot = int(s[-2]) in TC_BOOT_DIGITS
    ncip = int(s[-1])

    if hfun is None or ncip not in (1, 2, 3):
      return

    if boot:
      gen_skip(mode, "tcplay cannot create system-encryption (boot) volumes, so -m %d is not generated" % mode)
      return

    for tc_mode in range(3):
      cascade = TC_CASCADE_BY_COUNT.get(ncip, {}).get(tc_mode)

      if cascade is None:
        continue

      out = os.path.join(TC_TESTS_DIR, "hashcat_%s_%s.tc" % (hfun, cascade))

      if not os.path.exists(out):
        truecrypt_generate(mode, hfun, cascade, out, tmp)

    return

  if mode in VC_MODES:
    os.makedirs(VC_TESTS_DIR, exist_ok=True)

    s    = "%05d" % mode
    hfun = VC_HASH_DIGIT.get(int(s[3]))

    if hfun is None:
      return

    if int(s[3]) in VC_BOOT_DIGITS:
      gen_skip(mode, "veracrypt --create only writes normal volumes, so the boot mode -m %d is not generated" % mode)
      return

    for cascade in VC_CASCADES.get(int(s[4]), {}).values():
      out = os.path.join(VC_TESTS_DIR, "hashcat_%s_%s.vc" % (hfun, cascade))

      if not os.path.exists(out):
        veracrypt_generate(mode, hfun, cascade, out)

    return


# ---- archive generators (test.sh pkzip_test/gpg_test/rar_test/sevenzip_test/pdf_gen_test/ssh_test) ----

def gen_pkzip(args, mode, tmp):
  # Real ZipCrypto archives built with InfoZip 'zip', hash read back with John's zip2john.
  zip_bin  = _tool("ZIP_BIN", "zip")
  zip2john = _tool("ZIP2JOHN", "zip2john")

  if not shutil.which(zip_bin):
    gen_skip(mode, "'zip' not found (install InfoZip zip)")
    return

  if not _have(zip2john):
    gen_skip(mode, "zip2john not found (set ZIP2JOHN=/path/to/zip2john)")
    return

  pw   = CONTAINER_PASSWORD.decode("utf-8")
  zdir = os.path.join(tmp, "pkzip_%d" % mode)
  sdir = os.path.join(zdir, "src")
  os.makedirs(sdir, exist_ok=True)

  for i in (1, 2, 3, 4):
    with open(os.path.join(sdir, "t%d.txt" % i), "wb") as fh:
      fh.write(("pattern %d the quick brown fox " % i).encode() * 300)

  with open(os.path.join(sdir, "rand.bin"), "wb") as fh:
    fh.write(os.urandom(64))

  zf = os.path.join(zdir, "%d.zip" % mode)
  t  = lambda n: os.path.join(sdir, n)

  builds = {
    17200: ([zip_bin, "-9", "-e", "-P", pw, zf, t("t1.txt")], False),
    17210: ([zip_bin, "-0", "-e", "-P", pw, zf, t("t1.txt")], False),
    17220: ([zip_bin, "-9", "-e", "-P", pw, zf, t("t1.txt"), t("t2.txt"), t("t3.txt")], False),
    17225: ([zip_bin, "-e", "-P", pw, zf, t("t1.txt"), t("rand.bin"), t("t2.txt")], False),
    17230: ([zip_bin, "-9", "-e", "-P", pw, zf, t("t1.txt"), t("t2.txt"), t("t3.txt"), t("t4.txt")], True),
  }

  if mode not in builds:
    gen_skip(mode, "unsupported PKZIP mode for -g")
    return

  cmd, checksum = builds[mode]
  gen_run(cmd)

  hash_file = os.path.join(zdir, "%d.hash" % mode)
  extra     = ["-c"] if checksum else []
  rc, out   = gen_run([zip2john] + extra + [zf])
  token     = _john_extract(out, r"\$pkzip2?\$[^:]+")

  if token is None:
    gen_error(mode, "zip2john produced no hash for %s" % zf)
    return

  write_hash(hash_file, token)
  archive_crack(args, mode, hash_file, "PKZIP-container", tmp, fast=True)


def gen_gpg(args, mode, tmp):
  # Real GPG secret keys. gpg1 (GnuPG 1.4) does the classic CFB S2K variants directly; gpg (2.x) does
  # the default key and, for 17050, the on-disk OCB layout, read with tools/gpg-ocb-aes2hashcat.py.
  gpg1    = os.environ.get("GPG1_BIN", "gpg1")
  gpg2    = os.environ.get("GPG2_BIN", "gpg")
  gpg2john = _tool("GPG2JOHN", "gpg2john")
  ocb     = os.environ.get("GPG_OCB_EXTRACT", os.path.join(TDIR, "gpg-ocb-aes2hashcat.py"))

  if not _have(gpg2john):
    gen_skip(mode, "gpg2john not found (set GPG2JOHN=/path/to/gpg2john)")
    return

  have_gpg1 = shutil.which(gpg1) is not None

  if not have_gpg1:
    gen_note(mode, "%s (GnuPG 1.x) not found, so the classic S2K variants and the AES-128 (aux1) path "
                   "are skipped; set GPG1_BIN=... if installed elsewhere" % gpg1)

  pw   = CONTAINER_PASSWORD.decode("utf-8")
  gdir = os.path.join(tmp, "gpg_%d" % mode)
  os.makedirs(gdir, exist_ok=True)

  producers = []

  def gpg1_key(digest, cipher, label):
    if not have_gpg1:
      return

    home  = tempfile.mkdtemp()
    batch = ("Key-Type: RSA\nKey-Length: 1024\nKey-Usage: sign\nName-Real: %s\n"
             "Name-Email: %s@hashcat.test\nPassphrase: %s\nExpire-Date: 0\n%%commit\n"
             % (label, label, pw))
    gen_run([gpg1, "--homedir", home, "--batch", "--no-tty", "--s2k-digest-algo", digest,
             "--s2k-cipher-algo", cipher, "--s2k-mode", "3", "--s2k-count", "65536", "--gen-key"],
            stdin=batch.encode("utf-8"))

    rc, out = gen_run([gpg2john, os.path.join(home, "secring.gpg")])
    token   = _john_extract(out, r"\$gpg\$[^:]*")
    shutil.rmtree(home, ignore_errors=True)

    if token:
      producers.append((label, token))

  def gpg2_key(label, extra_args):
    home = tempfile.mkdtemp()
    gen_run([gpg2, "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", pw]
            + extra_args + ["--quick-generate-key", "%s <%s@hashcat.test>" % (label, label),
                            "rsa1024", "sign", "0"])
    rc, sk = gen_run([gpg2, "--homedir", home, "--batch", "--pinentry-mode", "loopback",
                      "--passphrase", pw, "--export-secret-keys"])
    sk_file = os.path.join(gdir, "%d_%s.sk.gpg" % (mode, label))

    with open(sk_file, "wb") as fh:
      fh.write(sk)

    rc, out = gen_run([gpg2john, sk_file])
    token   = _john_extract(out, r"\$gpg\$[^:]*")
    shutil.rmtree(home, ignore_errors=True)

    if token:
      producers.append((label, token))

  def gpg2_ocb_key(label, keytype):
    if not os.path.isfile(ocb):
      gen_skip(mode, "%s not found" % ocb)
      return

    home = tempfile.mkdtemp()
    gen_run([gpg2, "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", pw,
             "--quick-generate-key", "%s <%s@hashcat.test>" % (label, label), keytype, "sign", "0"])

    token = None
    keys  = glob.glob(os.path.join(home, "private-keys-v1.d", "*.key"))

    if keys:
      with open(keys[0], "rb") as fh:
        blob = fh.read()

      if b"openpgp-s2k3-ocb-aes" in blob:
        rc, out = gen_run([sys.executable, ocb, keys[0]])
        token   = _john_extract(out, r"\$gpg\$[^:]*")

    shutil.rmtree(home, ignore_errors=True)

    if token:
      producers.append((label, token))

  if mode == 17010:
    gpg1_key("SHA1", "AES", "gpg1-sha1-aes128")
    gpg1_key("SHA1", "AES256", "gpg1-sha1-aes256")
    gpg2_key("gpg2-default", [])
  elif mode == 17020:
    gpg1_key("SHA512", "AES", "gpg1-sha512-aes128")
    gpg1_key("SHA512", "AES256", "gpg1-sha512-aes256")
  elif mode == 17030:
    gpg1_key("SHA256", "AES", "gpg1-sha256-aes128")
    gpg1_key("SHA256", "AES256", "gpg1-sha256-aes256")
  elif mode == 17040:
    gpg1_key("SHA1", "CAST5", "gpg1-sha1-cast5")
  elif mode == 17050:
    gpg2_ocb_key("gpg2-ed25519-ocb", "ed25519")
    gpg2_ocb_key("gpg2-rsa2048-ocb", "rsa2048")
  else:
    gen_skip(mode, "unsupported GPG mode for -g")
    return

  if not producers:
    gen_skip(mode, "could not generate a matching GPG container (gpg1/gpg2 unavailable or mode unsupported by local tools)")
    return

  for label, token in producers:
    hash_file = os.path.join(gdir, "%d_%s.hash" % (mode, label))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "GPG-container %s" % label, tmp, fast=False)


def gen_rar(args, mode, tmp):
  # Real RAR archives. RAR3 (-ma4) needs a RARLAB rar 6.x or older; rar 7.x is RAR5 only. Hash read
  # back with John's rar2john.
  rar_bin = os.environ.get("RAR_BIN")

  if not rar_bin:
    old = os.path.join(os.path.expanduser("~"), "rar-old", "rar")
    rar_bin = old if os.path.exists(old) else "rar"

  rar2john = _tool("RAR2JOHN", "rar2john")

  if not _have(rar_bin):
    gen_skip(mode, "rar not found. Fetch rarlinux-x64-612.tar.gz from rarlab.com (NOT 'apt install rar', "
                   "that is rar 7.x = RAR5 only), or set RAR_BIN=/path/to/rar")
    return

  if not _have(rar2john):
    gen_skip(mode, "rar2john not found (set RAR2JOHN=/path/to/rar2john)")
    return

  pw   = CONTAINER_PASSWORD.decode("utf-8")
  rdir = os.path.join(tmp, "rar_%d" % mode)
  sdir = os.path.join(rdir, "src")
  os.makedirs(sdir, exist_ok=True)

  payload = os.path.join(sdir, "payload.txt")

  with open(payload, "wb") as fh:
    fh.write(b"pattern the quick brown fox jumps over the lazy dog " * 160)

  # Does this rar accept -ma4 (RAR3)?
  probe_dir = tempfile.mkdtemp()
  probe_txt = os.path.join(probe_dir, "p.txt")

  with open(probe_txt, "wb") as fh:
    fh.write(b"probe\n")

  probe_rar = os.path.join(probe_dir, "a.rar")
  gen_run([rar_bin, "a", "-ma4", "-p_", "-inul", probe_rar, probe_txt])
  has_ma4 = os.path.exists(probe_rar) and os.path.getsize(probe_rar) > 0
  shutil.rmtree(probe_dir, ignore_errors=True)

  if mode in (12500, 23700, 23800) and not has_ma4:
    gen_skip(mode, "%s cannot create RAR3 (-ma4), it is likely rar 7.x; fetch rarlinux-x64-612.tar.gz "
                   "from rarlab.com or set RAR_BIN=/path/to/rar<=6.x" % rar_bin)
    return

  arc   = os.path.join(rdir, "%d.rar" % mode)
  token_re = r"\$RAR3\$[^:]+"

  builds = {
    12500: ([rar_bin, "a", "-ma4", "-m3", "-hp" + pw, "-inul", arc, payload], "rar3-hp"),
    23700: ([rar_bin, "a", "-ma4", "-m0", "-p" + pw, "-inul", arc, payload], "rar3-p-store"),
    23800: ([rar_bin, "a", "-ma4", "-m3", "-p" + pw, "-inul", arc, payload], "rar3-p-compressed"),
    13000: ([rar_bin, "a", "-p" + pw, "-inul", arc, payload], "rar5"),
  }

  if mode not in builds:
    gen_skip(mode, "unsupported RAR mode for -g")
    return

  cmd, label = builds[mode]

  if mode == 13000:
    token_re = r"\$rar5\$[^:]+"

  gen_run(cmd)

  if not os.path.exists(arc) or os.path.getsize(arc) == 0:
    gen_error(mode, "rar failed to create %s" % arc)
    return

  hash_file = os.path.join(rdir, "%d.hash" % mode)
  rc, out   = gen_run([rar2john, arc])
  token     = _john_extract(out, token_re)

  if token is None:
    gen_error(mode, "rar2john produced no hash for %s" % arc)
    return

  write_hash(hash_file, token)
  archive_crack(args, mode, hash_file, "RAR-container %s" % label, tmp, fast=False)


def gen_sevenzip(args, mode, tmp):
  # 11600 from a 7-Zip archive (7z2john.pl), 13600 WinZip AES from a zip (zip2john). 11600 is built
  # four ways because the mode decrypts and decompresses a block and checks a CRC, so the codec is
  # part of what is under test.
  sevenzip = _tool("SEVENZIP_BIN", "7z")
  sz2john  = _tool("SEVENZIP2JOHN", "7z2john.pl")
  zip2john = _tool("ZIP2JOHN", "zip2john")

  if not shutil.which(sevenzip):
    gen_skip(mode, "7z not found (apt install p7zip-full, or set SEVENZIP_BIN=/path/to/7z)")
    return

  pw   = CONTAINER_PASSWORD.decode("utf-8")
  sdir = os.path.join(tmp, "7z_%d" % mode)
  os.makedirs(sdir, exist_ok=True)

  payload = os.path.join(sdir, "payload.txt")

  with open(payload, "wb") as fh:
    fh.write(b"pattern the quick brown fox jumps over the lazy dog " * 160)

  if mode == 11600:
    if not _have(sz2john):
      gen_skip(mode, "7z2john.pl not found (set SEVENZIP2JOHN=/path/to/7z2john.pl)")
      return

    if subprocess.run(["perl", "-MCompress::Raw::Lzma", "-e", "1"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
      gen_skip(mode, "7z2john.pl needs Compress::Raw::Lzma (apt install libcompress-raw-lzma-perl)")
      return

    variants = [("lzma2-header-encrypted", ["-mhe=on"]), ("lzma2-header-plain", ["-mhe=off"]),
                ("stored", ["-mhe=on", "-m0=Copy"]), ("bzip2", ["-mhe=on", "-m0=BZip2"])]
  elif mode == 13600:
    if not _have(zip2john):
      gen_skip(mode, "zip2john not found (set ZIP2JOHN=/path/to/zip2john)")
      return

    variants = [("aes128", ["-mem=AES128"]), ("aes256", ["-mem=AES256"])]
  else:
    gen_skip(mode, "unsupported 7z mode for -g")
    return

  for label, opts in variants:
    if mode == 13600:
      archive   = os.path.join(sdir, "%d_%s.zip" % (mode, label))
      gen_run([sevenzip, "a", "-tzip"] + opts + ["-p" + pw, archive, payload])
      rc, out   = gen_run([zip2john, archive])
      token     = _john_extract(out, r"\$zip2\$[^:]*")
    else:
      archive   = os.path.join(sdir, "%d_%s.7z" % (mode, label))
      gen_run([sevenzip, "a"] + opts + ["-p" + pw, archive, payload])
      rc, out   = gen_run(["perl", sz2john, archive])
      token     = _john_extract(out, r"\$7z\$[^:]*")

    if token is None:
      gen_error(mode, "could not read a hash out of the generated %s archive" % label)
      continue

    hash_file = os.path.join(sdir, "%d_%s.hash" % (mode, label))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "7z-container %s" % label, tmp, fast=False)


def gen_pdf(args, mode, tmp):
  # Encrypted PDFs built with qpdf (gs writes the plain document it encrypts), hash read with
  # pdf2john.pl. qpdf 11 refuses RC4 without --allow-weak-crypto.
  qpdf     = _tool("QPDF_BIN", "qpdf")
  pdf2john = _tool("PDF2JOHN", "pdf2john.pl")

  if not shutil.which(qpdf):
    gen_skip(mode, "qpdf not found (apt install qpdf, or set QPDF_BIN=/path/to/qpdf)")
    return

  if not _have(pdf2john):
    gen_skip(mode, "pdf2john.pl not found (set PDF2JOHN=/path/to/pdf2john.pl); the .py needs pyhanko and is not used here")
    return

  pw   = CONTAINER_PASSWORD.decode("utf-8")
  pdir = os.path.join(tmp, "pdf_%d" % mode)
  os.makedirs(pdir, exist_ok=True)

  plain = os.path.join(pdir, "plain.pdf")

  if shutil.which("gs"):
    gen_run(["gs", "-q", "-o", plain, "-sDEVICE=pdfwrite", "-c", "showpage"])

  if not os.path.exists(plain) or os.path.getsize(plain) == 0:
    gen_skip(mode, "no gs to write a plain PDF for qpdf to encrypt (apt install ghostscript)")
    return

  # opts as they follow qpdf, PW standing in for the password, "--" ending the encrypt options.
  variants = {
    10400: [("rc4-40", ["--allow-weak-crypto", "--encrypt", pw, pw, "40", "--"])],
    10500: [("rc4-128", ["--allow-weak-crypto", "--encrypt", pw, pw, "128", "--"]),
            ("aes-128", ["--encrypt", pw, pw, "128", "--use-aes=y", "--"])],
    10700: [("aes-256", ["--encrypt", pw, pw, "256", "--"])],
  }

  if mode not in variants:
    gen_skip(mode, "unsupported PDF mode for -g")
    return

  for label, opts in variants[mode]:
    doc = os.path.join(pdir, "%d_%s.pdf" % (mode, label))
    gen_run([qpdf] + opts + [plain, doc])

    if not os.path.exists(doc) or os.path.getsize(doc) == 0:
      gen_skip(mode, "qpdf could not write a %s document" % label)
      continue

    rc, out = gen_run(["perl", pdf2john, doc])
    token   = _john_extract(out, r"\$pdf\$[^:]*")

    if token is None:
      gen_error(mode, "pdf2john produced no hash for the %s document" % label)
      continue

    hash_file = os.path.join(pdir, "%d_%s.hash" % (mode, label))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "PDF-container %s" % label, tmp, fast=False)


def gen_ssh(args, mode, tmp):
  # A real OpenSSH private key. -m PEM writes the classic DEK-Info form the 229xx modes parse; the
  # default openssh-key-v1 layout is bcrypt-pbkdf, which no released mode reads. Read with ssh2john.py.
  keygen  = _tool("SSHKEYGEN_BIN", "ssh-keygen")
  ssh2john = _tool("SSH2JOHN", "ssh2john.py")

  if not shutil.which(keygen):
    gen_skip(mode, "ssh-keygen not found (set SSHKEYGEN_BIN=/path/to/ssh-keygen)")
    return

  if not _have(ssh2john):
    gen_skip(mode, "ssh2john.py not found (set SSH2JOHN=/path/to/ssh2john.py)")
    return

  pw   = CONTAINER_PASSWORD.decode("utf-8")
  kdir = os.path.join(tmp, "ssh_%d" % mode)
  os.makedirs(kdir, exist_ok=True)

  for keytype in ("rsa", "dsa"):
    key = os.path.join(kdir, "%d_%s" % (mode, keytype))

    for stale in (key, key + ".pub"):
      if os.path.exists(stale):
        os.remove(stale)

    gen_run([keygen, "-q", "-m", "PEM", "-t", keytype, "-N", pw, "-C", "hashcat", "-f", key])

    if not os.path.exists(key) or os.path.getsize(key) == 0:
      gen_skip(mode, "ssh-keygen would not write a PEM %s key" % keytype)
      continue

    rc, out = gen_run([sys.executable, ssh2john, key])
    token   = _john_extract(out, r"\$sshng\$[^:]*")

    if token is None:
      gen_error(mode, "ssh2john produced no hash for the %s key" % keytype)
      continue

    hash_file = os.path.join(kdir, "%d_%s.hash" % (mode, keytype))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "SSH-key %s" % keytype, tmp, fast=False)


ARCHIVE_GENERATORS = [
  (PKZIP_GEN_MODES,    gen_pkzip),
  (GPG_GEN_MODES,      gen_gpg),
  (RAR_GEN_MODES,      gen_rar),
  (SEVENZIP_GEN_MODES, gen_sevenzip),
  (PDF_GEN_MODES,      gen_pdf),
  (SSH_GEN_MODES,      gen_ssh),
]


def run_generate_archive(args, mode, tmp):
  # -g adds a real-artifact test for the archive families, on top of the mode's .py oracle.
  for modes, fn in ARCHIVE_GENERATORS:
    if mode in modes:
      fn(args, mode, tmp)


CONTAINER_MODES = ({14600, 34100} | set(LUKS1_HASH_CIPHER) | TC_MODES | VC_MODES | CL_MODES)

# Modes that ship a module but cannot have a crack test, with the reason. --test-coverage reports any
# mode with neither an oracle nor container coverage nor a self-test that is not on this list, so it
# fails when a new mode arrives without one.

COVERAGE_UNTESTABLE = {
  2000:  "STDOUT candidate generator (OPTS_TYPE_SELF_TEST_DISABLE), nothing to crack",
  2501:  "WPA-EAPOL-PMK, deprecated, superseded by 22001",
  16801: "WPA-PMKID-PMK, deprecated, superseded by 22001",
  9710:  "MS Office <= 2003 MD5 + RC4 collider #1, not a wordlist or mask crack",
  9720:  "MS Office <= 2003 MD5 + RC4 collider #2, not a wordlist or mask crack",
  9810:  "MS Office <= 2003 SHA1 + RC4 collider #1, not a wordlist or mask crack",
  9820:  "MS Office <= 2003 SHA1 + RC4 collider #2, not a wordlist or mask crack",
  10410: "PDF 1.1 - 1.3 collider #1, not a wordlist or mask crack",
  10420: "PDF 1.1 - 1.3 collider #2, not a wordlist or mask crack",
}


def module_hash_name(mode):
  m = re.search(rb'HASH_NAME\s*=\s*"([^"]*)"', module_source(mode))

  return m.group(1).decode("utf-8", "replace") if m else ""


def run_test_coverage():
  # Which modes test.py can test, and which ship a module without a way to. Reads the source tree
  # only, so it needs no built hashcat and no backend device. Was tools/test_coverage.sh.

  all_modes = sorted(int(re.search(r"module_0*([0-9]+)\.c$", p).group(1))
                     for p in glob.glob(os.path.join(ROOT, "src", "modules",
                                                     "module_[0-9][0-9][0-9][0-9][0-9].c")))

  # CONTAINER_MODES carries the cryptoloop kernel numbers (14511..14553) as labels; every one runs
  # hashcat with -m 14500, the only module that exists, so collapse them to it for this check.
  container = {14600, 34100} | set(LUKS1_HASH_CIPHER) | TC_MODES | set(VC_MODES) | {14500}
  covered   = set(discover_modes()) | container | SELFTEST_MODES

  missing = sorted(m for m in all_modes if m not in covered and m not in COVERAGE_UNTESTABLE)
  orphans = sorted(container - set(all_modes))

  n_uncovered = sum(1 for m in all_modes if m not in covered)

  print("modules      : %d" % len(all_modes))
  print("with a test  : %d" % (len(all_modes) - n_uncovered))
  print("excluded     : %d" % len(COVERAGE_UNTESTABLE))
  print("")

  if orphans:
    print("Listed as a container mode but no such module exists:")

    for m in orphans:
      print("  %d" % m)

    print("")

  if not missing:
    print("Every mode has a test or a documented reason not to.")

    return 1 if orphans else 0

  print("No test and no documented reason:")

  for m in missing:
    print("  %-6d %s" % (m, module_hash_name(m)))

  print("")
  print("Add tools/test_modules/m<mode>.py, or add the mode to COVERAGE_UNTESTABLE in test.py")
  print("with the reason it cannot have one.")

  return 1

# test.sh -M's 24 hash types, one representative per family, covering all distinct code paths
# (test.sh). The container families contribute their first mode (6211, 13711, 14511, 29511, 34100)
# plus LUKS1 legacy 14600, all now handled by the container full-test above.
MINIMAL_MODES = [0, 100, 110, 400, 500, 2600, 3000, 3200, 6211, 11600, 12500, 13711, 14200, 14511,
                 14600, 14900, 15400, 15700, 20510, 22000, 29511, 33000, 33500, 34100]


def selftest_status(rc):
  # test.sh status() as container_run_and_report calls it (test.sh): bucket the raw hashcat
  # exit code. Unlike the oracle attacks there is no cracked-but-not-matched rewrite, because the
  # self-test path checks the exit code alone, not the output.

  e = {"ce": 0, "rs": 0, "to": 0, "nf": 0, "nm": 0}

  if rc == 0:
    return e

  if rc == 246 or rc == 30 or rc in (248, 249, 250, 251, 252, 253):
    e["rs"] += 1
  elif rc == 1:
    e["nf"] += 1
  elif rc == 4:
    e["to"] += 1
  elif rc == 10:
    e["nm"] += 1
  elif rc == 20:
    e["ce"] += 1
    e["nm"] += 1
  else:
    e["nf"] += 1

  return e


def selftest_verdict(e):
  # test.sh container_run_and_report's message (test.sh), with cnt fixed at 1.

  if e["ce"]:
    return "Compare Error"

  if e["rs"]:
    return "Skip"

  if e["nf"] or e["nm"]:
    return "Error"

  if e["to"]:
    return "Warning"

  return "OK"


def selftest_context(args, mode, attack, width_label):
  # Like context() but for the self-test line: it always says single, carries the width as a label so
  # the sweep can pass "default", and ends with the ", self-test vector" tag container_run_and_report
  # adds (test.sh).

  dev = device_for(args, mode)

  return ("[ test.py ] [ Type %d, Attack %d, Mode single, Device-Type %s, Kernel-Type %s, "
          "Vector-Width %s, self-test vector ]"
          % (mode, attack, DEVICE_LABEL.get(dev, dev),
             "Pure" if args.pure else "Optimized", width_label))


def selftest_vector_test(args, opts, mode, attack, width_label, tmp):
  # test.sh selftest_vector_test (test.sh): crack a mode's own example hash. Returns the output
  # lines (a Skip, an Error, or the one report line) so the caller can print them and, for the sweep,
  # read the verdict back. attack 65535 means -a all, which this path runs as a single -a 0 run.

  if attack == 65535:
    attack = 0

  lines = []

  vector = selftest_vector_read(mode)

  if vector is None:
    lines.append("[ test.py ] [ Type %d ] > Skip : no self-test vector published by --hash-info"
                 % mode)

    return lines

  vhash, vpass, vfmt, deprecated = vector

  hash_file = os.path.join(tmp, "%d_selftest.hash" % mode)

  if vfmt == "N/A":
    lines.append("[ test.py ] [ Type %d ] > Skip : mode has no example hash to crack" % mode)

    return lines

  selftest_write_hash(mode, vhash, vfmt, hash_file)

  if not os.path.isfile(hash_file) or os.path.getsize(hash_file) == 0:
    lines.append("[ test.py ] [ Type %d ] > Error : could not write the self-test vector to %s"
                 % (mode, hash_file))
    note_verdict("Error")

    return lines

  extra = build_container_extra(mode, attack, vpass, tmp)

  if extra is None:
    return lines

  if deprecated:
    # A deprecated mode is refused without this (test.sh).
    extra = extra + ["--deprecated-check-disable"]

  # The startup self test would re-derive the same vector on every launch, so skip it and let the
  # run itself be the test (test.sh).

  extra = extra + ["--self-test-disable"]

  rc, _ = run_hashcat(opts, mode, hash_file, None, attack=attack, extra=extra)

  e   = selftest_status(rc)
  msg = selftest_verdict(e)

  lines.append("%s > %s : %d/1 not found, %d/1 not matched, %d/1 timeout, %d/1 skipped"
               % (selftest_context(args, mode, attack, width_label),
                  msg, e["nf"], e["nm"], e["to"], e["rs"]))
  note_verdict(msg)

  return lines


def run_selftest_normal(args, mode, widths, tmp):
  # test.sh normal run (test.sh): a slow SELFTEST_MODES member cracks its own example hash once
  # per vector width, with the requested attack (-a all becomes -a 0 inside selftest_vector_test).

  attack = 65535 if args.attack == "all" else int(args.attack)

  for width in widths:
    opts = base_opts(args) + ["--backend-vector-width", str(width)]

    for line in selftest_vector_test(args, opts, mode, attack, str(width), tmp):
      print(line)


def selftest_opts(args):
  # test.sh -S run options: the base options with --runtime 60 and no --backend-vector-width, since
  # the sweep leaves VECTOR at "default" (test.sh).

  opts = ["--quiet", "--potfile-disable", "--logfile-disable"]

  opts += ISOLATION

  if not args.pure:
    opts.append("-O")

  opts += ["--runtime", str(SELFTEST_RUNTIME), "-D", args.device]

  if args.force:
    opts.append("--force")

  return opts


def sweep_range(spec):
  # test.sh's -S range: "all" walks every mode hashcat reports, a single value or a range narrows it
  # (test.sh). Returns (lo, hi, all_modes).

  if spec == "all":
    return (0, 0, True)

  if re.fullmatch(r"[0-9]+", spec):
    v = int(spec)

    return (v, v, False)

  m = re.fullmatch(r"([0-9]+)-([0-9]+)", spec)

  if m is None:
    die("! invalid hash type selected: %s" % spec)

  lo, hi = int(m.group(1)), int(m.group(2))

  if lo > hi:
    die("! invalid hash type range: %d-%d" % (lo, hi))

  return (lo, hi, False)


def selftest_sweep_modes():
  # The hash-modes hashcat itself reports, which is the sweep set: it reaches modes with no oracle.
  proc = subprocess.run([BIN, "--hash-info"], cwd=ROOT,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

  modes = []

  for line in proc.stdout.split(b"\n"):
    m = re.fullmatch(rb"Hash mode #([0-9]+)", line)

    if m is not None:
      modes.append(int(m.group(1)))

  return modes


def selftest_vector_sweep(args):
  # test.sh selftest_vector_sweep (test.sh): crack every hash-mode's own example hash, or the
  # ones in the -m range, and print one line per mode that did not crack. Returns the exit code.
  # A --selftest-child run (a -j worker) prints only its per-mode lines; run_parallel_selftest
  # prints the header and the summary from the gathered verdicts.

  lo, hi, all_modes = sweep_range(args.mode)

  if args.selftest_child:
    # The parent already picked the real hash-info modes and hands each child a single one, so the
    # child skips the --hash-info enumeration, which is redundant and races across many workers.
    sweep_modes = list(range(lo, hi + 1))
  else:
    sweep_modes = selftest_sweep_modes()

    if not sweep_modes:
      print("! could not read the hash-mode list from %s --hash-info" % BIN)

      return 1

  opts = selftest_opts(args)

  sweep_total = 0
  sweep_ok    = 0
  sweep_bad   = ""
  sweep_slow  = ""
  sweep_na    = ""

  if not args.selftest_child:
    print("[ test.py ] > Cracking every hash-mode's own self-test vector")

  with tempfile.TemporaryDirectory(prefix="test_py_") as tmp:
    for sweep_mode in sweep_modes:
      if not all_modes and (sweep_mode < lo or sweep_mode > hi):
        continue

      out_lines = selftest_vector_test(args, opts, sweep_mode, 0, "default", tmp)

      for line in out_lines:
        print(line)

      if sweep_mode in NO_SELFTEST:
        sweep_na += "%d " % sweep_mode
        continue

      sweep_total += 1

      text = "\n".join(out_lines)

      # test.sh buckets on the captured output. Its SKIPPED_LIST check for a skipped mode always
      # falls through to "did not crack", because selftest_vector_test runs in a $(...) subshell and
      # its record_skip never reaches the parent's list (test.sh). So anything that is not
      # OK or Warning, a skip included, is counted as not cracked, and print_skip_summary at the end
      # of the sweep prints nothing.

      if "> OK :" in text:
        sweep_ok += 1
      elif "> Warning :" in text:
        sweep_slow += "%d " % sweep_mode
      else:
        sweep_bad += "%d " % sweep_mode

  if not args.selftest_child:
    selftest_print_summary(sweep_ok, sweep_total, sweep_slow, sweep_na, sweep_bad)

  return 1 if sweep_bad else 0


def selftest_print_summary(sweep_ok, sweep_total, sweep_slow, sweep_na, sweep_bad):
  print("")
  print("[ test.py ] > %d/%d hash-modes cracked their own self-test vector"
        % (sweep_ok, sweep_total))

  if sweep_slow:
    print("[ test.py ] > hit --runtime %d, rerun those with -r: %s"
          % (SELFTEST_RUNTIME, sweep_slow))

  if sweep_na:
    print("[ test.py ] > no self-test vector, not checked: %s" % sweep_na)

  if sweep_bad:
    print("[ test.py ] > did not crack: %s" % sweep_bad)


def run_parallel_selftest(args):
  # Fan the self-test sweep across args.jobs workers, one mode per child, the same shape as
  # run_parallel. Each child is a single-mode -S run in its own process, so setup_isolation() gives
  # it a private hashcat cache and session. The child prints only its per-mode line; the header and
  # the summary are printed here from the gathered verdicts, so a -j run reads like the serial sweep.
  sweep_modes = selftest_sweep_modes()

  if not sweep_modes:
    print("! could not read the hash-mode list from %s --hash-info" % BIN)

    return 1

  lo, hi, all_modes = sweep_range(args.mode)
  selected = [m for m in sweep_modes if all_modes or (lo <= m <= hi)]

  base = [sys.executable, os.path.abspath(__file__), "-S", "--selftest-child",
          "-D", args.device]

  if args.pure:
    base.append("-P")

  if args.force:
    base.append("-f")

  def run_one(mode):
    proc = subprocess.run(base + ["-m", str(mode)],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    return proc.stdout

  sweep_total = 0
  sweep_ok    = 0
  sweep_slow  = ""
  sweep_na    = ""
  sweep_bad   = ""

  print("[ test.py ] > Cracking every hash-mode's own self-test vector")

  with ThreadPoolExecutor(max_workers=args.jobs) as pool:
    for mode, out in zip(selected, pool.map(run_one, selected)):
      sys.stdout.buffer.write(out)
      sys.stdout.buffer.flush()

      if mode in NO_SELFTEST:
        sweep_na += "%d " % mode
        continue

      sweep_total += 1
      record("modes")

      text = out.decode("utf-8", "replace")

      if "> OK :" in text:
        sweep_ok += 1
        record("OK")
      elif "> Warning :" in text:
        sweep_slow += "%d " % mode
        record("Warning")
      else:
        sweep_bad += "%d " % mode
        record("not-OK")

  selftest_print_summary(sweep_ok, sweep_total, sweep_slow, sweep_na, sweep_bad)

  return 1 if sweep_bad else 0


def widths_for(spec):
  if spec in ("default", "all"):
    return [1, 4]

  if spec in ("1", "4"):
    return [int(spec)]

  die("! -V takes 1, 4, or default (both); got '%s'" % spec)


def targets_for(spec):
  if spec == "all":
    return ["single", "multi"]

  return [spec]


def base_opts(args):
  # --deprecated-check-disable matches test.sh's global OPTS: 2500/2501/16800/16801 are deprecated
  # plugins hashcat refuses to run without it, and it is a no-op for every non-deprecated mode.
  opts = ["--quiet", "--potfile-disable", "--logfile-disable", "--deprecated-check-disable"]

  opts += ISOLATION

  if not args.pure:
    opts.append("-O")

  opts += ["--runtime", str(RUNTIME), "-D", args.device]

  # The depth -j split pins each worker to one backend device with -d, so its instances do not share a
  # card. -D stays as the type, which the pinned device already is.
  if args.backend_devices:
    opts += ["--backend-devices", args.backend_devices]

  if args.force:
    opts.append("--force")

  return opts


STDOUT_MODE = 2000


def run_stdout_roundtrip(args, tmp):
  # 2000 (STDOUT) has an empty kernel (OpenCL/m02000_mxx is a no-op) and never cracks, so there is
  # no digest to test. The test is a round trip instead: every word fed to "hashcat --stdout -a 0"
  # must come back byte for byte. The words come from the same seeded oracle both engines use, forced
  # pure because --stdout has no kernel family, so test.sh and test.py check the identical set.
  env = dict(os.environ, IS_OPTIMIZED="0")

  proc = subprocess.run([sys.executable, RUNNER, "single", str(STDOUT_MODE)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  if proc.returncode != 0:
    die("! oracle failed for mode %d (rc=%d):\n%s"
        % (STDOUT_MODE, proc.returncode, proc.stderr.decode("utf-8", "replace").rstrip()))

  words = [m.group(1).rstrip(b" ") for m in (LINE.match(l) for l in proc.stdout.splitlines()) if m]

  wfile = os.path.join(tmp, "m%05d_stdout_words" % STDOUT_MODE)

  with open(wfile, "wb") as fh:
    fh.write(b"\n".join(words) + (b"\n" if words else b""))

  cmd = [BIN, "--stdout", "-a", "0"] + ISOLATION

  if args.force:
    cmd.append("--force")

  got = subprocess.run(cmd + [wfile], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
  got_lines = got.splitlines()

  cnt = len(words)
  nf  = sum(1 for i, w in enumerate(words) if i >= len(got_lines) or got_lines[i] != w)

  msg = "OK" if (nf == 0 and cnt > 0) else "Error"

  print("[ test.py ] [ Type %d, STDOUT round-trip ] > %s : %d/%d not found, 0/%d not matched, "
        "0/%d timeout, 0/%d skipped" % (STDOUT_MODE, msg, nf, cnt, cnt, cnt, cnt))

  note_verdict(msg)


# The edge-testing path (a port of tools/test_edge.sh). For each mode it drives the min and max
# password and salt lengths the module declares, across every attack type, kernel type, vector
# width and target type, and checks hashcat cracks them. It shares the oracle engine
# (tools/test_module_runner.py, the "edge" subcommand), setup_isolation() and the -j fan-out with
# the crack-verification path above. Only modes with a .py oracle are reachable here, so the .pm
# only modes test_edge.sh covers through the perl engine are left to test_edge.sh.

EDGE_ATTACKS    = [0, 1, 3, 4, 6, 7, 8, 9, 12]
EDGE_WHOLE_WORD = (0, 4, 8, 9)
EDGE_WIDTHS     = [1, 2, 4, 8, 16]
EDGE_RUNTIME    = 270

# 2000 (STDOUT) has an empty kernel and never cracks, so edge-cracking it only makes errors
# (test_edge.sh SKIP_HASH_TYPES). The deprecated WPA modes are dropped by the -HH check instead.

EDGE_SKIP_MODES = {2000}

# 14000/14100/31500/31600 crack a plaintext other than the one the hash was made from, and
# 22000/22001 write the handshake parts rather than hash and plaintext, so their outfile cannot be
# compared to what the oracle generated (test_edge.sh SKIP_OUT_MATCH_HASH_TYPES).

EDGE_SKIP_OUT_MATCH = {14000, 14100, 22000, 22001, 31500, 31600}

# The modes whose -HH says same-salt is "Not" allowed but that the suite runs with a shared salt
# anyway (test_edge.sh SKIP_SAME_SALT_HASH_TYPES, the active list).

EDGE_SKIP_SAME_SALT = {6600, 7100, 7200, 8200, 13200, 13400, 15300, 15310, 15900, 15910, 16900,
                       18300, 18900, 20200, 20300, 20400, 27000, 27100, 29700, 29930, 29940}

EDGE_HH_CACHE = {}


def _w(path, data):
  with open(path, "wb") as fh:
    fh.write(data)


def edge_as_bytes(x):
  if isinstance(x, bytes):
    return x

  return os.fsencode(x)


def edge_run(opts, mode, target, stdin_bytes, attack, extra):
  # Like run_hashcat, but every argument is bytes, because an edge hash, salt or mask can carry a
  # byte that is not valid ASCII and subprocess will not mix str and bytes in one argv.

  argv = [os.fsencode(BIN)]
  argv += [edge_as_bytes(o) for o in opts]
  argv += [edge_as_bytes(o) for o in bridge_opts(mode)]
  argv += [b"-a", str(attack).encode("ascii"), b"-m", str(mode).encode("ascii")]
  argv += [edge_as_bytes(target)]
  argv += [edge_as_bytes(x) for x in extra]

  proc = subprocess.run(argv, input=stdin_bytes, cwd=ROOT,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  return proc.returncode, proc.stdout + proc.stderr


def edge_echo_norm(data):
  # bash 'echo ${var}' with the value unquoted: word splitting collapses every run of whitespace to
  # one space and trims the ends. test_edge.sh compares the md5 of two such strings, which is the
  # same as comparing the strings, so the single-hash check compares these return values directly.

  return b" ".join(data.split())


def edge_sort_lines(data):
  # 'sort -s' over a byte stream. A trailing newline is not an extra empty line, and under the C
  # locale the order is a plain byte order, which sorted() gives.

  lines = data.split(b"\n")

  if lines and lines[-1] == b"":
    lines.pop()

  return sorted(lines)


def edge_strip_userpw(data):
  # test_edge.sh runs the outfile through sed 's/    (user password.*$//g' before comparing, so a
  # mode that appends a note to the plaintext line still matches. Applied per line here.

  return re.sub(rb"    \(user password[^\n]*", b"", data)


def edge_noise_words(word, slow, suffix):
  # test_edge.sh noise_words: the tail of the word replaced by every digit, with the word itself put
  # back in the middle of them, so a word-list attack has to pick the right candidate out of noise
  # rather than being handed it alone. 100 variants on a fast hash, 10 on a slow one.

  cut_len = 1 if slow else 2

  if len(word) < cut_len:
    cut_len = len(word)

  if cut_len == 0:
    return [word + suffix]

  if cut_len == 2:
    tails = [("%d%d" % (a, b)).encode("ascii") for a in range(10) for b in range(10)]
  else:
    tails = [("%d" % a).encode("ascii") for a in range(10)]

  stem = word[:len(word) - cut_len]

  half = len(tails) // 2

  out = []

  for at, tail in enumerate(tails):
    if at == half:
      out.append(word + suffix)

    out.append(stem + tail + suffix)

  return out


def edge_mask_for(tok, text):
  # test_edge.sh mask_for: a mask of len(text) copies of tok. For '?d' the positions that are not
  # ASCII digits are spelled as literals, because no '?d' produces a byte above 0x7f.

  out = tok * len(text)

  if tok == b"?d":
    return mask_literalize(out, text)

  return out


def edge_build_ruleset(ruleset, context_lines):
  # test_edge.sh: the smallest pcfg that emits exactly this list. X1 at probability 1 is one flat
  # terminal per Context line, so the run is as long as the list and emits nothing else.

  shutil.rmtree(ruleset, ignore_errors=True)

  os.makedirs(os.path.join(ruleset, "Grammar"))
  os.makedirs(os.path.join(ruleset, "Context"))

  _w(os.path.join(ruleset, "Grammar", "grammar.txt"), b"X1\t1.0\n")
  _w(os.path.join(ruleset, "Context", "1.txt"), b"".join(l + b"\n" for l in context_lines))


def edge_oracle(mode, attack, optimized):
  # The edge vectors for one mode, attack and kernel family, from the same engine test_edge.sh's
  # run_oracle uses. Each line is mode,attack,optimized,word_len,salt_len,word_hex,salt_hex,hash_hex;
  # the fields are hex so a comma or quote in the value never splits the line.

  proc = subprocess.run([sys.executable, RUNNER, "edge", str(mode), str(attack),
                         "1" if optimized else "0"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

  vectors = []

  for line in proc.stdout.split(b"\n"):
    if not line:
      continue

    fields = line.split(b",", 7)

    if len(fields) < 8:
      continue

    try:
      word_len = int(fields[3])
      salt_len = int(fields[4])
    except ValueError:
      continue

    # bytes.fromhex of an empty field is b"". The rstrip mirrors the way test_edge.sh reads each
    # field through a command substitution, which strips a value's trailing newlines.

    word = bytes.fromhex(fields[5].decode("ascii")).rstrip(b"\n") if fields[5] else b""
    salt = bytes.fromhex(fields[6].decode("ascii")).rstrip(b"\n") if fields[6] else b""
    dig  = bytes.fromhex(fields[7].decode("ascii")).rstrip(b"\n") if fields[7] else b""

    vectors.append({"word_len": word_len, "salt_len": salt_len,
                    "word": word, "salt": salt, "hash": dig})

  return vectors, proc.returncode


def edge_hh(mode):
  # The one run of 'hashcat -m N -HH' test_edge.sh does many times over, parsed once here. Every
  # field test_edge.sh reads off -HH is pulled out the same way its grep and awk do.

  if mode in EDGE_HH_CACHE:
    return EDGE_HH_CACHE[mode]

  # -HH is run with ISOLATION, not just the crack itself: it initialises the backend to read
  # Kernel.Type(s) and so touches the kernel cache, and two -j workers sharing the default cache
  # race and one comes back without the kernel line, which reads as "no kernel type" and a false
  # error. A private --cache-path per worker removes the shared state.

  proc = subprocess.run([BIN, "-m", str(mode), "-HH"] + ISOLATION, cwd=ROOT,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

  info = {"deprecated": False, "kernel_types": [], "slow": False, "salt_present": False,
          "salt_virtual": False, "pw_type": "", "cnt_max": -1, "same_salt_not": False,
          "keep_guessing": False}

  for line in proc.stdout.decode("utf-8", "replace").split("\n"):
    parts = line.split()

    if "Deprecated.." in line:
      info["deprecated"] = len(parts) > 1 and parts[1] == "Yes"
    elif "Kernel.Type(s" in line:
      info["kernel_types"] = line.split(":", 1)[1].replace(",", "").split()
    elif "Slow.Hash" in line:
      info["slow"] = len(parts) > 1 and parts[1] == "Yes"
    elif "Salt.Type" in line:
      info["salt_present"] = True
      info["salt_virtual"] = len(parts) > 1 and parts[1] == "Virtual"
    elif "Password.Type" in line:
      info["pw_type"] = parts[1] if len(parts) > 1 else ""
    elif "Hashes.Count.Max" in line:
      if len(parts) > 1 and re.fullmatch(r"-?[0-9]+", parts[1]):
        info["cnt_max"] = int(parts[1])
    elif "Same.Salt" in line:
      info["same_salt_not"] = len(parts) > 1 and parts[1] == "Not"
    elif "Keep.Guessing" in line:
      info["keep_guessing"] = len(parts) > 1 and parts[1] == "Yes"

  EDGE_HH_CACHE[mode] = info

  return info


def edge_binary_hashfile(mode):
  # A mode that takes the path of a container file (test_edge.sh BINARY_HASHFILE_TYPES). The
  # OPTIONAL variant accepts the hash as text too, so it is left out.

  src = module_source(mode)

  return b"OPTS_TYPE_BINARY_HASHFILE" in src and b"OPTS_TYPE_BINARY_HASHFILE_OPTIONAL" not in src


def edge_hexify_plain(mode):
  # A mode whose plaintext hashcat writes as bare hex (test_edge.sh HEXIFY_PLAIN_TYPES). A mode that
  # also reads its candidate as hex is left out.

  src = module_source(mode)

  return b"OPTS_TYPE_PT_ALWAYS_HEXIFY" in src and b"OPTS_TYPE_PT_HEX" not in src


class EdgeCtx:
  # The per-mode facts an attack cell needs, read once off -HH and the module source.

  def __init__(self, mode, attack, ktype, optimized, hh, slow, binary,
               pt_hex, pt_base58, hexify_plain, no_salt, keep_guessing):
    self.mode         = mode
    self.attack       = attack
    self.ktype        = ktype
    self.optimized    = optimized
    self.hh           = hh
    self.slow         = slow
    self.binary       = binary
    self.pt_hex       = pt_hex
    self.pt_base58    = pt_base58
    self.hexify_plain = hexify_plain
    self.no_salt      = no_salt
    self.keep_guessing = keep_guessing


def edge_a3_split(ctx, word, word_len):
  # test_edge.sh attack_type 3: the tail becomes a '?d' run rewritten to spell it, the head trails
  # as literals, and the two are one argument so a split inside a character still reassembles.

  if ctx.pt_hex:
    return word[:-2], b"?b"

  if ctx.pt_base58:
    return word[:-2], b"?a?a"

  if word_len == 2:
    w1, mask = word[:-1], b"?d"
  elif ctx.slow:
    w1, mask = word[:-2], b"?d?d"
  else:
    w1, mask = word[:-3], b"?d?d?d"

  return w1, mask_literalize(mask, word[len(w1):])


def edge_a6_split(ctx, word, word_len):
  # test_edge.sh attack_type 6: word on the left, mask on the right. The word ends on a character
  # boundary and the mask spells whatever that leaves.

  if ctx.pt_hex:
    return word[:-2], b"?b"

  if ctx.pt_base58:
    return word[:-2], b"?a?a"

  tail_len = 1 if (word_len == 2 or ctx.slow) else 2
  split    = utf8_split_point(word, len(word) - tail_len)

  return word[:split], edge_mask_for(b"?d", word[split:])


def edge_a7_split(ctx, word, word_len):
  # test_edge.sh attack_type 7: mask on the left, word on the right.

  if ctx.pt_hex:
    return word[2:], b"?b"

  if ctx.pt_base58:
    return word[2:], b"?a?a"

  head_len = 1 if (word_len == 2 or ctx.slow) else 2
  split    = utf8_split_point(word, head_len)

  return word[split:], edge_mask_for(b"?d", word[:split])


def edge_a12_split(ctx, word):
  # test_edge.sh attack_type 12: a mask on both sides of the word, the shape 6 and 7 cannot reach,
  # the two sides sharing the budget those spend on one. A word with nothing left once a mask
  # character is taken off each end, and a slow hash, get the mask in front of the word instead.

  mask_c   = b"?d"
  cut_len  = 1
  both     = True

  if ctx.pt_hex:
    mask_c, cut_len, both = b"?b", 2, False
  elif ctx.pt_base58:
    mask_c = b"?a"

  if ctx.slow:
    both = False

  left  = cut_len
  right = len(word) - cut_len

  if mask_c == b"?d":
    left  = utf8_split_point(word, left)
    right = utf8_split_point(word, right)

  mid_len = right - left

  if both and mid_len >= 1:
    w1 = word[left:right]

    if mask_c == b"?d":
      mask = edge_mask_for(b"?d", word[:left]) + b"?w" + edge_mask_for(b"?d", word[right:])
    else:
      mask = mask_c + b"?w" + mask_c
  else:
    w1 = word[left:]

    if mask_c == b"?d":
      mask = edge_mask_for(b"?d", word[:left]) + b"?w"
    else:
      mask = mask_c + b"?w"

  return w1, mask


def edge_single_cmd(ctx, word, word_len, i, tmp):
  # The argv after the hash, and the stdin, for one single-hash edge vector. Mirrors the per-attack
  # branches test_edge.sh builds in its single-hash loop.

  attack = ctx.attack
  pfx    = os.path.join(tmp, "edge_s_%d_%s_%d_%d" % (ctx.mode, ctx.ktype, attack, i))

  if attack == 0:
    return [], word + b"\n"

  if attack == 1:
    off = utf8_split_point(word, word_len // 2)
    f1  = pfx + ".1.word"
    f2  = pfx + ".2.word"

    _w(f1, word[:off] + b"\n")
    _w(f2, word[off:] + b"\n")

    return [f1, f2], None

  if attack == 3:
    w1, mask = edge_a3_split(ctx, word, word_len)

    return [w1 + mask], None

  if attack == 6:
    w1, mask = edge_a6_split(ctx, word, word_len)
    f = pfx + "_1.word"

    _w(f, w1)

    return [f, mask], None

  if attack == 7:
    w1, mask = edge_a7_split(ctx, word, word_len)
    f = pfx + "_2.word"

    _w(f, w1)

    return [mask, f], None

  if attack == 12:
    w1, mask = edge_a12_split(ctx, word)
    f = pfx + "_12.word"

    _w(f, w1)

    return [mask, f], None

  if attack == 4:
    ruleset = pfx + ".ruleset"

    edge_build_ruleset(ruleset, edge_noise_words(word, ctx.slow, b"\t1.0"))

    return [ruleset], None

  if attack == 8:
    f = pfx + "_8.word"

    _w(f, b"".join(l + b"\n" for l in edge_noise_words(word, ctx.slow, b"")))

    return ["wordlist", f], None

  if attack == 9:
    f = pfx + "_9.word"

    _w(f, word + b"\n")

    return [f], None

  return [], None


def edge_single(ctx, width, opts, outfile, vectors, tmp):
  errors = 0
  cells  = 0

  for i, v in enumerate(vectors, start=1):
    word     = v["word"]
    word_len = v["word_len"]
    dig      = v["hash"]

    word_compare = None

    if ctx.mode == 20510:
      # PKZIP master key reports a plaintext that is not the candidate; the candidate is the word
      # without its first 6 bytes (test_edge.sh).
      word_compare = word
      word         = word[6:]

    if ctx.hexify_plain:
      word_compare = word.hex().encode("ascii")

    if ctx.mode == 20510 and word_len <= 6 and len(word) == 0 and ctx.attack in (3, 6, 7, 12):
      continue

    # A -a 4 grammar cannot write an empty word or one holding a tab (test_edge.sh
    # attack_rejects_word), so that vector is skipped rather than failed.

    if ctx.attack == 4 and (len(word) == 0 or b"\t" in word):
      continue

    if ctx.binary:
      # A container path hashcat prints back verbatim: an existing path is used as is (a LUKS image
      # the module built), otherwise the base64 hash is decoded into a file (test_edge.sh).
      if os.path.exists(dig):
        target = dig
      else:
        target = os.fsencode(os.path.join(tmp, "edge_%d_%s_%d_%d.hashfile"
                             % (ctx.mode, ctx.ktype, ctx.attack, i)))

        _w(target, base64.b64decode(dig))

      hash_out = target
    else:
      target   = dig
      hash_out = dig

    extra, stdin = edge_single_cmd(ctx, word, word_len, i, tmp)

    try:
      os.remove(outfile)
    except OSError:
      pass

    rc, _ = edge_run(opts, ctx.mode, target, stdin, ctx.attack, extra)

    cells += 1

    if rc != 0:
      if rc == 252:
        break

      errors += 1

      print("[ test.py edge ] !> error (%d) Type %d, Attack %d, Kernel %s, Vector %d, Test %d, single"
            % (rc, ctx.mode, ctx.attack, ctx.ktype, width, i))

      if rc == 250:
        break

      continue

    if ctx.mode in EDGE_SKIP_OUT_MATCH or ctx.keep_guessing:
      continue

    try:
      with open(outfile, "rb") as fh:
        raw = fh.read()
    except OSError:
      raw = b""

    got  = edge_echo_norm(edge_strip_userpw(raw))
    want = edge_echo_norm(hash_out + b":" + (word_compare if word_compare is not None else word))

    if got != want:
      errors += 1

      print("[ test.py edge ] !> mismatch Type %d, Attack %d, Kernel %s, Vector %d, Test %d, single"
            % (ctx.mode, ctx.attack, ctx.ktype, width, i))

  return errors, cells


def edge_multi_cmd(ctx, selected, width, tmp):
  # The argv after the hash file, and the stdin, for the multi-hash run. Mirrors test_edge.sh's
  # per-attack multi branches, which build one word or mask file across the selected vectors.

  attack = ctx.attack
  pfx    = os.path.join(tmp, "edge_m_%d_%s_%d_%d" % (ctx.mode, ctx.ktype, attack, width))

  if attack == 0:
    return [], b"".join(w + b"\n" for w, _, _, _ in selected)

  if attack == 1:
    f1 = pfx + ".1.words"
    f2 = pfx + ".2.words"
    heads = []
    tails = []

    for word, word_len, _, _ in selected:
      off = utf8_split_point(word, word_len // 2)

      heads.append(word[:off])
      tails.append(word[off:])

    _w(f1, b"".join(x + b"\n" for x in heads))
    _w(f2, b"".join(x + b"\n" for x in tails))

    return [f1, f2], None

  if attack == 3:
    masks = pfx + ".masks"
    lines = []

    for word, word_len, _, _ in selected:
      w1, mask = edge_a3_split(ctx, word, word_len)

      lines.append(w1 + mask)

    _w(masks, b"".join(x + b"\n" for x in lines))

    return [masks], None

  if attack in (6, 7, 12):
    wf = pfx + ".words"
    mf = pfx + ".masks"
    ws = []
    ms = []

    for word, word_len, _, _ in selected:
      if attack == 6:
        w1, mask = edge_a6_split(ctx, word, word_len)
      elif attack == 7:
        w1, mask = edge_a7_split(ctx, word, word_len)
      else:
        w1, mask = edge_a12_split(ctx, word)

      ws.append(w1)
      ms.append(mask)

    _w(wf, b"".join(x + b"\n" for x in ws))
    _w(mf, b"".join(x + b"\n" for x in ms))

    if attack == 6:
      return [wf, mf], None

    return [mf, wf], None

  if attack == 4:
    # test_edge.sh's multi ruleset is one Context entry per hash's word, each carrying its own
    # probability, so the words of the other hashes are the noise this attack tests against.
    ruleset = pfx + ".ruleset"

    edge_build_ruleset(ruleset, [w + b"\t1.0" for w, _, _, _ in selected])

    return [ruleset], None

  if attack == 8:
    wf = pfx + ".words"

    _w(wf, b"".join(w + b"\n" for w, _, _, _ in selected))

    return ["wordlist", wf], None

  if attack == 9:
    wf = pfx + ".words"

    _w(wf, b"".join(w + b"\n" for w, _, _, _ in selected))

    return [wf], None

  return [], None


def edge_multi(ctx, width, opts, outfile, vectors, tmp):
  mode   = ctx.mode
  attack = ctx.attack
  hh     = ctx.hh

  cnt_max = hh["cnt_max"]

  if mode == 20510 or ctx.binary:
    cnt_max = 1

  # A mode that loads at most one hash has no multi run; nor does -a 9 on a mode where every hash is
  # on the one salt, since -a 9 takes one candidate per salt (test_edge.sh).

  if cnt_max == 1:
    return 0, 0, False

  if attack == 9 and ctx.no_salt:
    return 0, 0, False

  same_salt = True

  if mode not in EDGE_SKIP_SAME_SALT and hh["same_salt_not"]:
    same_salt = False

  if attack == 9:
    same_salt = False

  if not vectors:
    return 0, 0, False

  selected   = []
  salts_seen = set()
  hash_cnt   = 0

  for v in vectors:
    if cnt_max > 1 and hash_cnt > cnt_max:
      continue

    word     = v["word"]
    word_len = v["word_len"]
    salt     = v["salt"]
    salt_len = v["salt_len"]
    dig      = v["hash"]

    word_compare = None

    if mode == 20510:
      word_compare = word
      word         = word[6:]

    if ctx.hexify_plain:
      word_compare = word.hex().encode("ascii")

    if not ctx.no_salt and not same_salt:
      key = (salt_len, salt)

      if key in salts_seen:
        continue

      salts_seen.add(key)

    if attack == 4 and (len(word) == 0 or b"\t" in word):
      continue

    hash_cnt += 1

    selected.append((word, word_len, word_compare, dig))

  # test_edge.sh runs the multi case only with two or more hashes.

  if hash_cnt <= 1:
    return 0, 0, False

  use_compare = ctx.hexify_plain or mode == 20510

  hash_in = os.path.join(tmp, "edge_m_%d_%s_%d_%d.hashes" % (mode, ctx.ktype, attack, width))

  hcout  = []
  hlines = []

  for word, word_len, word_compare, dig in selected:
    hlines.append(dig)

    wline = word_compare if (use_compare and word_compare is not None) else word

    hcout.append(dig + b":" + wline)

  _w(hash_in, b"".join(h + b"\n" for h in hlines))

  extra, stdin = edge_multi_cmd(ctx, selected, width, tmp)

  try:
    os.remove(outfile)
  except OSError:
    pass

  rc, out = edge_run(opts, mode, hash_in, stdin, attack, extra)

  if rc != 0:
    if rc == 252:
      return 0, 1, True

    # -a 9 wants one iteration count across the whole set; a mixed set is the attack saying what it
    # takes, not a defect (test_edge.sh).

    if attack == 9 and b"Mixed iteration counts are not supported" in out:
      return 0, 1, False

    print("[ test.py edge ] !> error (%d) Type %d, Attack %d, Kernel %s, Vector %d, multi"
          % (rc, mode, attack, ctx.ktype, width))

    return 1, 1, rc == 250

  if mode in EDGE_SKIP_OUT_MATCH or ctx.keep_guessing:
    return 0, 1, False

  try:
    with open(outfile, "rb") as fh:
      raw = fh.read()
  except OSError:
    raw = b""

  got  = edge_sort_lines(edge_strip_userpw(raw).rstrip(b"\n") + b"\n")
  want = edge_sort_lines(b"".join(l + b"\n" for l in hcout))

  if got != want:
    print("[ test.py edge ] !> mismatch Type %d, Attack %d, Kernel %s, Vector %d, multi"
          % (mode, attack, ctx.ktype, width))

    return 1, 1, False

  return 0, 1, False


def edge_process_mode(args, mode, cfg, tmp):
  # One mode's whole edge run: the skip gates, then every attack, kernel, width and target the
  # options ask for. Returns (errors, cells).

  if mode in EDGE_SKIP_MODES:
    print("[ test.py edge ] > Skip Type %d (common)" % mode)

    return 0, 0

  hh = edge_hh(mode)

  if hh["deprecated"]:
    print("[ test.py edge ] > Skip Type %d (is deprecated)" % mode)

    return 0, 0

  slow         = hh["slow"]
  binary       = edge_binary_hashfile(mode)
  hexify_plain = edge_hexify_plain(mode)
  no_salt      = (not hh["salt_present"]) or hh["salt_virtual"]
  pt_hex       = hh["pw_type"] == "HEX"
  pt_base58    = hh["pw_type"] == "BASE58" or mode in (31500, 31600)
  keep_guess   = hh["keep_guessing"]

  errors = 0
  cells  = 0

  for attack in cfg["attacks"]:
    kernel_types = hh["kernel_types"]

    # No kernel family means nothing to test; test_edge.sh counts that as an error rather than a
    # green run that tested nothing.

    if not kernel_types:
      print("[ test.py edge ] !> error Type %d: -HH names no kernel type" % mode)

      errors += 1

      continue

    for ktype in kernel_types:
      optimized = ktype == "optimized"

      if cfg["kernel_filter"] is not None and cfg["kernel_filter"] != (1 if optimized else 0):
        continue

      # -a 4 amplifies on the device for a mode whose kernel runs inside, and that engine has a pure
      # kernel only unless the mode ships mNNNNN_a4-optimized.cl, so an optimized -a 4 pass on such a
      # mode has nothing to run (test_edge.sh).

      if attack == 4 and optimized and not slow and not a4_optimized(mode):
        continue

      if cfg["exec_filter"] is not None and (1 if slow else 0) not in cfg["exec_filter"]:
        continue

      # A slow mode runs only the whole-word attacks when the full suite is selected, since -a 0
      # covers the same candidates and the mask attacks cost too much there (test_edge.sh). This only
      # fires when the -m selection is all or a range, not a single mode, and never for 400.

      if slow and (cfg["exec_filter"] is None or 1 in cfg["exec_filter"]):
        if 0 in cfg["attacks_set"] and not cfg["all_attacks"]:
          if attack not in EDGE_WHOLE_WORD and cfg["all_scope"] and mode != 400:
            continue

      vectors, _ = edge_oracle(mode, attack, optimized)

      if not vectors or not vectors[0]["hash"]:
        print("[ test.py edge ] !> error Type %d: empty test vectors" % mode)

        errors += 1

        break

      ctx = EdgeCtx(mode, attack, ktype, optimized, hh, slow, binary,
                    pt_hex, pt_base58, hexify_plain, no_salt, keep_guess)

      for width in cfg["widths"]:
        outfile = os.path.join(tmp, "edge_%d_%s_%d_%d.outfile" % (mode, ktype, attack, width))
        opts    = edge_opts(args, optimized, width, pt_hex, outfile)

        if 0 in cfg["targets"]:
          e, c = edge_single(ctx, width, opts, outfile, vectors, tmp)

          errors += e
          cells  += c

        if 1 in cfg["targets"]:
          e, c, stop = edge_multi(ctx, width, opts, outfile, vectors, tmp)

          errors += e
          cells  += c

          if stop:
            break

  return errors, cells


def edge_opts(args, optimized, width, pt_hex, outfile):
  # test_edge.sh's global OPTS plus the per-kernel and per-width flags, with test.py's ISOLATION
  # appended so any number of runs share no mutable state.

  opts = ["--quiet", "--potfile-disable", "--machine-readable", "--logfile-disable"]

  opts += ISOLATION
  opts += ["-D", args.device, "--runtime", str(EDGE_RUNTIME), "--self-test-disable"]

  if args.force:
    opts.append("--force")

  if optimized:
    opts.append("-O")

  opts += ["--backend-vector-width", str(width)]

  if pt_hex:
    opts.append("--hex-charset")

  opts += ["--outfile", outfile]

  return opts


def edge_select_modes(spec, modes):
  # test_edge.sh's -m rules over the .py oracle set: a single value must be a member, a range must
  # intersect it, "all" is every member.

  if spec == "all":
    return modes

  if re.fullmatch(r"[0-9]+", spec):
    ht = int(spec)

    if ht not in modes:
      die("! hash type %d has no tools/test_modules/m%05d.py, so test.py --edge cannot run it"
          % (ht, ht))

    return [ht]

  m = re.fullmatch(r"([0-9]+)-([0-9]+)", spec)

  if m is None:
    die("! invalid hash type selected: %s" % spec)

  lo, hi = int(m.group(1)), int(m.group(2))

  if lo > hi:
    die("! invalid hash type range: %d-%d" % (lo, hi))

  hit = [ht for ht in modes if lo <= ht <= hi]

  if not hit:
    die("! no hash type between %d and %d has a python oracle" % (lo, hi))

  return hit


def edge_parse_attacks(spec):
  if spec == "all":
    return list(EDGE_ATTACKS)

  out = []

  for tok in spec.split(","):
    if not re.fullmatch(r"0|1|3|4|6|7|8|9|12", tok):
      die("! invalid attack type: %s" % tok)

    out.append(int(tok))

  return out


def edge_parse_widths(spec):
  # For --edge, an unset -V (test.py's "default") means every width, as test_edge.sh's default does.

  if spec in ("all", "default"):
    return list(EDGE_WIDTHS)

  out = []

  for tok in spec.split(","):
    if not re.fullmatch(r"1|2|4|8|16", tok):
      die("! invalid vector width: %s" % tok)

    out.append(int(tok))

  return out


def edge_parse_kernel(spec):
  if spec == "all":
    return None

  if spec in ("0", "1"):
    return int(spec)

  die("! invalid kernel type: %s (0 pure, 1 optimized, all)" % spec)


def edge_parse_targets(spec):
  if spec == "all":
    return {0, 1}

  if spec == "single":
    return {0}

  if spec == "multi":
    return {1}

  die("! invalid target type: %s" % spec)


def edge_parse_exec(spec):
  if spec == "all":
    return None

  out = set()

  for tok in spec.split(","):
    if tok not in ("0", "1"):
      die("! invalid attack exec: %s (0 inside kernel, 1 outside kernel, all)" % tok)

    out.add(int(tok))

  return out


def run_parallel_edge(args, modes, all_scope):
  # Fan the edge run across args.jobs workers, one mode per child, the same shape as run_parallel.
  # Each child is a plain single-mode --edge run, so setup_isolation() gives it a private cache and
  # session. The child prints only its per-mode line; the total is summed and printed here.

  base = [sys.executable, os.path.abspath(__file__), "--edge", "--edge-child",
          "-a", args.attack, "-t", args.target, "-D", args.device,
          "-V", args.vector, "-K", args.kernel, "-A", args.attack_exec]

  if args.force:
    base.append("-f")

  if args.allow_all_attacks:
    base.append("--allow-all-attacks")

  if all_scope:
    base.append("--edge-all-scope")

  def run_one(mode):
    proc = subprocess.run(base + ["-m", str(mode)],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    return proc.stdout

  total = 0

  with ThreadPoolExecutor(max_workers=args.jobs) as pool:
    for out in pool.map(run_one, modes):
      sys.stdout.buffer.write(out)
      sys.stdout.buffer.flush()

      record("modes")

      for m in re.finditer(rb"> (\d+) errors,", out):
        total += int(m.group(1))

      PROGRESS["errors"] = total

  print("[ test.py edge ] > Errors detected: %d" % total)

  return 1 if total else 0


def run_edge(args):
  modes    = discover_modes()
  selected = edge_select_modes(args.mode, modes)

  # test_edge.sh only narrows the slow-mode mask-attack skip to a single -m N; a range keeps its
  # "all" scope. --edge-all-scope carries that decision into a -j child, which always sees one mode.

  all_scope = args.edge_all_scope or not re.fullmatch(r"[0-9]+", args.mode)

  attacks     = edge_parse_attacks(args.attack)
  widths      = edge_parse_widths(args.vector)
  kernel      = edge_parse_kernel(args.kernel)
  targets     = edge_parse_targets(args.target)
  exec_filter = edge_parse_exec(args.attack_exec)

  # test_edge.sh refuses -a 4 -K 1 on a single mode whose kernel runs inside and that ships no
  # optimized pcfg kernel, because every cell would be skipped.

  if attacks == [4] and kernel == 1 and re.fullmatch(r"[0-9]+", args.mode):
    m   = int(args.mode)
    src = module_source(m)

    if src and b"ATTACK_EXEC_OUTSIDE_KERNEL" not in src and not a4_optimized(m):
      die("! attack type 4 has no optimized kernel for hash type %d, and -K 1 asks for the\n"
          "! optimized one only. Ask for the pure kernel type instead: --edge -m %d -a 4 -K 0"
          % (m, m))

  if args.jobs > 1 and not args.edge_child:
    return run_parallel_edge(args, selected, all_scope)

  cfg = {"attacks": attacks, "attacks_set": set(attacks), "widths": widths,
         "kernel_filter": kernel, "targets": targets, "exec_filter": exec_filter,
         "all_attacks": args.allow_all_attacks, "all_scope": all_scope}

  total_err  = 0
  total_cell = 0

  with tempfile.TemporaryDirectory(prefix="test_py_edge_") as tmp:
    for mode in selected:
      e, c = edge_process_mode(args, mode, cfg, tmp)

      total_err  += e
      total_cell += c

      print("[ test.py edge ] [ Type %d ] > %d errors, %d cells" % (mode, e, c))

  # A -j child prints only its per-mode lines; run_parallel_edge sums and prints the total.

  if not args.edge_child:
    print("[ test.py edge ] > Errors detected: %d" % total_err)

  return 1 if total_err else 0


def run_parallel(args):
  # The breadth -j split: fan the selected modes across args.jobs workers, so as many modes as
  # possible are in flight and the whole run finishes in the least time. More workers than devices is
  # normal, so the workers share each card and export_worker_mem_shares has capped each to its slice of
  # the memory. Each worker is a plain single-mode test.py run (no -j) in its own process, so
  # setup_isolation() gives it a private hashcat cache/session and no two runs share mutable state.
  # One mode per child means a kernel is still built only once. Output is gathered and printed in mode
  # order, so a -j run reads the same as the serial run.
  modes = MINIMAL_MODES if args.minimal else select_modes(args.mode, discover_modes())

  base = [sys.executable, os.path.abspath(__file__),
          "-a", args.attack, "-t", args.target, "-D", args.device, "-V", args.vector]

  if args.pure:
    base.append("-P")

  if args.force:
    base.append("-f")

  def run_one(mode):
    proc = subprocess.run(base + ["-m", str(mode)],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    return proc.returncode, proc.stdout

  rc = 0
  retry = []

  # Submit the dearest modes first. A mode is indivisible, so the longest one sets the floor for any
  # job count, and submitting in mode order leaves it starting late: on the -M set the three dearest
  # sit at positions 10 to 12 of 24, so with 8 workers none of them begins until a cheap mode frees a
  # slot. ATTACK_EXEC_OUTSIDE_KERNEL is the cost proxy, read off the module rather than kept in a
  # table that would go stale, and on that set it names the five dearest modes exactly. A mode it
  # names wrongly is cheap and gives its slot straight back, so a false positive costs nothing.
  #
  # Results are still read in mode order, so the output of a -j run is unchanged.

  order = sorted(modes, key=lambda m: (0 if host_engine(m) else 1, -m))

  with ThreadPoolExecutor(max_workers=args.jobs) as pool:
    submitted = {m: pool.submit(run_one, m) for m in order}

    for mode in modes:
      prc, out = submitted[mode].result()

      if prc == MEMSKIP_RC:
        # Skipped only because -j gave this worker a fraction of the card. Defer it and re-run on the
        # whole card below, so its memory-skip output here is left out.
        retry.append(mode)
        continue

      sys.stdout.buffer.write(out)
      sys.stdout.buffer.flush()

      # The parent prints the children's lines but keeps its own tally by mode, so a Ctrl-C total is
      # meaningful here too. A child buckets by attack line; the parent by whole mode.
      record("modes")
      record("OK" if prc == 0 else "not-OK")

      if prc != 0:
        rc = 1

  if retry:
    # Re-run the memory-capped skips one at a time with the two caps removed, so the memory-heavy modes
    # are still covered. A mode that needs more than the whole card skips again, now a
    # genuine skip with no cap set.
    nocap = {k: v for k, v in os.environ.items()
             if k not in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT")}

    print("[ test.py ] > re-running %d memory-capped skip(s) without the cap: %s"
          % (len(retry), " ".join(str(m) for m in retry)))
    sys.stdout.flush()

    for mode in retry:
      proc = subprocess.run(base + ["-m", str(mode)], env=nocap,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

      sys.stdout.buffer.write(proc.stdout)
      sys.stdout.buffer.flush()

      record("modes")
      record("OK" if proc.returncode == 0 else "not-OK")

      if proc.returncode != 0:
        rc = 1

  return rc


def run_parallel_depth(args):
  # The depth -j split: one mode at a time per device, each pinned to a single card at its whole
  # memory, rather than many modes sharing every card on a fraction of it (run_parallel). The point is
  # to give each mode a full device, so concurrency is the number of devices of the -D type, not the
  # -j number, and no memory cap is set (main() skips export_worker_mem_shares for this split). A
  # device pulls the next mode when it finishes its last, and output is printed in mode order, as the
  # breadth split and the serial run do.
  modes = MINIMAL_MODES if args.minimal else select_modes(args.mode, discover_modes())

  ids = backend_ids_for(args.device)

  if ids:
    slots = ids
    # Announce the resolved slots so a live run shows which physical cards the split pinned to, one per
    # device of the -D type after the alias twins are removed.
    print("[ test.py ] > depth split: %d device slot(s), backend ids %s" % (len(ids), ids))
  else:
    # -I named no backend device of the -D type (an older hashcat, a parse miss, or a filtered box).
    # Run one unpinned worker rather than none, but say so: the depth split exists to give each mode a
    # whole device, and here it has fallen back to a single worker instead of one per card.
    slots = [None]
    print("[ test.py ] > warning: depth split found no backend device of type -D %s in hashcat -I; "
          "running one unpinned worker" % args.device)

  base = [sys.executable, os.path.abspath(__file__),
          "-a", args.attack, "-t", args.target, "-D", args.device, "-V", args.vector]

  if args.pure:
    base.append("-P")

  if args.force:
    base.append("-f")

  free = queue.Queue()

  for dev in slots:
    free.put(dev)

  def run_one(mode):
    dev = free.get()

    try:
      # A bridged mode picks its own host device (bridge_opts forces the CPU), so it is not pinned to
      # this slot's card, but it still holds the slot so only len(slots) run at once.
      pin = [] if (dev is None or is_bridged(mode)) else ["-d", str(dev)]

      proc = subprocess.run(base + pin + ["-m", str(mode)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

      return proc.returncode, proc.stdout
    finally:
      free.put(dev)

  rc = 0

  with ThreadPoolExecutor(max_workers=len(slots)) as pool:
    for mode, (prc, out) in zip(modes, pool.map(run_one, modes)):
      sys.stdout.buffer.write(out)
      sys.stdout.buffer.flush()

      record("modes")
      record("OK" if prc == 0 else "not-OK")

      if prc != 0:
        rc = 1

  return rc


def bridge_family(mode):
  # The bridge hashes in Python, so it has no kernel of its own and the optimized/pure split does not
  # apply to the crack. It still draws its candidates from the mode's oracle, which offers one
  # constraint set per family (word slot 0 is pure, slot 2 is optimized; [-1, -1] means that family
  # has no kernel). So pick the family the mode actually has, preferring pure, which covers almost
  # every mode; a few dozen are optimized only. Returns "p", "o", or None when the mode has an oracle
  # with neither, so there is nothing to generate.
  tests = os.path.join(TDIR, "test_modules")
  path  = os.path.join(tests, "m%05d.py" % mode)

  if not os.path.isfile(path):
    return None

  # The oracle modules import their shared helpers as "lib.test_helpers", so their directory has to
  # be importable the way test_bridge.py and the runner make it.
  if tests not in sys.path:
    sys.path.insert(0, tests)

  spec = importlib.util.spec_from_file_location("bridge_family_m%05d" % mode, path)
  mod  = importlib.util.module_from_spec(spec)

  spec.loader.exec_module(mod)

  pairs    = mod.module_constraints()
  has_pure = not (pairs[0][0] == -1 and pairs[0][1] == -1)
  has_opt  = not (pairs[2][0] == -1 and pairs[2][1] == -1)

  if has_pure:
    return "p"

  if has_opt:
    return "o"

  return None


def bridge_vectors(mode, family, hash_path, word_path):
  # Build bridge-format vectors for a mode from its own oracle, through tools/test_bridge.py, under
  # the given family ("p" or "o"; see bridge_family). Returns the vector count, or -1 when none could
  # be made: oracle error, or every hash too long for the bridge's 1024 byte salt.
  cmd = [sys.executable, os.path.join(TDIR, "test_bridge.py"), "vectors", str(mode), hash_path, word_path]

  if family == "p":
    cmd.append("-P")

  proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  if proc.returncode != 0 or not os.path.isfile(hash_path):
    return -1

  with open(hash_path, "rb") as fh:
    return sum(1 for line in fh if line.strip())


# A cracked bridge line is "<sha256 hex>*<mode>:<family>:<base64>:<password>", so a line that opens
# with the 64 hex digit digest and a star is one recovered hash.
BRIDGE_CRACK = re.compile(rb"(?m)^[0-9a-f]{64}\*")


def run_bridge(args):
  # Crack every selected mode's own test oracle through the Python bridge (mode 73000), with -a 0 and
  # no mode kernel, so hashcat's parser and candidate handling are checked against the reference
  # implementation. test_bridge.py builds the vectors and is itself the bridge module. One hashcat
  # run per mode is one test cell: it passes only when every vector the oracle produced is recovered.
  # The bridge hashes in Python, so the optimized/pure split does not apply; bridge_family picks the
  # family only to draw valid candidates from the oracle, and -P on the run is ignored here.
  bridge_py = os.path.join(TDIR, "test_bridge.py")
  modes     = MINIMAL_MODES if args.minimal else select_modes(args.mode, discover_modes())

  # mode 73000 has no optimized or pure kernel of its own, so -O does not apply to the bridge run.
  opts = [o for o in base_opts(args) if o != "-O"]

  with tempfile.TemporaryDirectory(prefix="test_py_bridge_") as tmp:
    for mode in modes:
      hpath = os.path.join(tmp, "m%05d.hash" % mode)
      wpath = os.path.join(tmp, "m%05d.words" % mode)

      label  = "[ test.py ] [ Type %d, Bridge, Device-Type Cpu ]" % mode
      family = bridge_family(mode)

      if family is None:
        print("%s > Skip : mode has no oracle to drive the bridge" % label)
        record("Skip")
        note_verdict("Skip")

        continue

      n = bridge_vectors(mode, family, hpath, wpath)

      if n <= 0:
        print("%s > Skip : oracle produced no bridge vectors" % label)
        record("Skip")
        note_verdict("Skip")

        continue

      rc, out = run_hashcat(opts, 73000, hpath, None, attack=0,
                            extra=["--bridge-parameter1", bridge_py, wpath])

      cracked = len(BRIDGE_CRACK.findall(out))

      c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

      classify(rc, cracked == n, c)

      v = verdict(c)

      print("%s > %s : %d/%d not found, %d/%d not matched, %d/%d timeout, %d/%d skipped%s"
            % (label, v, n - cracked if rc == 0 else 0, n, 0, n, 0, n, 0, n,
               (", %d/%d errors" % (c["err"], c["cnt"])) if c.get("err") else ""))

      record(v)
      note_verdict(v)

  return 1 if ERRORS else 0


def main():
  # Line-buffer stdout so the serial paths (-S, single mode) stream under CI, where stdout is a
  # pipe Python would otherwise block-buffer. The -j paths already flush by hand.
  try:
    sys.stdout.reconfigure(line_buffering=True)
  except (AttributeError, ValueError):
    pass

  ap = argparse.ArgumentParser(description="python manager for the hashcat -a 0 test path")

  ap.add_argument("-m", dest="mode", default="all", help="N | all | min-max")
  ap.add_argument("-a", dest="attack", default=None,
                  help="0 | 1 | 3 | 4 | 6 | 7 | 8 | 9 | 12 | all (--edge takes a comma list too)")
  ap.add_argument("-t", dest="target", default="all", choices=["single", "multi", "all"])
  ap.add_argument("-D", dest="device", default="2", help="OpenCL device type")
  ap.add_argument("-d", dest="backend_devices", default=None, help=argparse.SUPPRESS)
  # -O is accepted and does nothing, as in test.sh where optimized is already the default; -P is
  # what switches to the pure kernel, and if both are given -P wins.
  ap.add_argument("-O", dest="optimized", action="store_true", help="optimized kernels (default)")
  ap.add_argument("-P", dest="pure", action="store_true", help="pure kernels")
  ap.add_argument("--bridge", dest="bridge", action="store_true",
                  help="crack each mode's own test oracle through the Python bridge (-m 73000), no mode kernel")
  ap.add_argument("-f", dest="force", action="store_true", help="pass --force to hashcat")
  ap.add_argument("-V", dest="vector", default="default", help="1 | 4 | default (both)")
  ap.add_argument("-S", dest="selftest_all", action="store_true",
                  help="crack every mode's own self-test vector (the -m range, or all modes)")
  ap.add_argument("-M", dest="minimal", action="store_true",
                  help="minimal mode: full-test the 24 hash types covering all distinct code paths")
  ap.add_argument("-g", dest="generate", action="store_true",
                  help="build a real container/archive and crack that, in addition to (archives) or "
                       "in place of (LUKS/TrueCrypt/VeraCrypt) the shipped one; LUKS and TrueCrypt "
                       "need sudo. On its own runs every mode -g can build.")
  ap.add_argument("--test-coverage", dest="test_coverage", action="store_true",
                  help="report modes with no test and exit; reads the source tree, needs no hashcat")
  ap.add_argument("--compute-sanitizer", dest="compute_sanitizer", nargs="?", const="memcheck",
                  default=None, metavar="TOOL",
                  help="run the CUDA kernels under NVIDIA Compute Sanitizer (memcheck|racecheck|"
                       "synccheck|initcheck, default memcheck); CUDA-only, needs ./hashcat-sanitizer")
  ap.add_argument("-j", dest="jobs", type=int, default=1,
                  help="run modes in parallel, each in its own hashcat cache/session; see --split")
  ap.add_argument("--split", dest="split", choices=["breadth", "depth"], default="breadth",
                  help="-j strategy: breadth runs this many modes at once, each a slice of a shared "
                       "card (most modes in the least time); depth runs one mode per device at that "
                       "device's full memory, so -j opts in but the device count sets the concurrency")
  ap.add_argument("--logdir", dest="logdir", nargs="?", const=AUTO_LOGDIR, default=None,
                  help="name the output folder (default test_<ts>/, as test.sh); it holds logfull.txt, "
                       "the reason and the cmdline for every skip and error")
  ap.add_argument("--edge", dest="edge", action="store_true",
                  help="edge-case testing (the port of tools/test_edge.sh)")
  ap.add_argument("-K", dest="kernel", default="all", help="--edge: 0 pure | 1 optimized | all")
  ap.add_argument("-A", dest="attack_exec", default="all",
                  help="--edge: 0 inside kernel | 1 outside kernel | all")
  ap.add_argument("--allow-all-attacks", dest="allow_all_attacks", action="store_true",
                  help="--edge: run mask attacks on ATTACK_EXEC_OUTSIDE_KERNEL modes too")
  ap.add_argument("--edge-all-scope", dest="edge_all_scope", action="store_true",
                  help=argparse.SUPPRESS)
  ap.add_argument("--edge-child", dest="edge_child", action="store_true",
                  help=argparse.SUPPRESS)
  ap.add_argument("--selftest-child", dest="selftest_child", action="store_true",
                  help=argparse.SUPPRESS)

  args = ap.parse_args()

  # --test-coverage reads the source tree only, so it runs before the isolation and binary checks.
  if args.test_coverage:
    sys.exit(run_test_coverage())

  # --compute-sanitizer points hashcat at the sweep shim, which wraps every run in
  # tools/compute_sanitizer/run.py under NVIDIA Compute Sanitizer and routes findings into a results
  # directory. The same BIN indirection test.sh used, so the rest of the run is unchanged.
  if args.compute_sanitizer is not None:
    global BIN

    sanitizer_bin = os.path.join(ROOT, "hashcat-sanitizer")

    if not os.path.isfile(sanitizer_bin):
      die("! no %s; build it first with tools/compute_sanitizer/run.py build" % sanitizer_bin)

    sweep_dir = os.path.join(TDIR, "compute_sanitizer", "results", "sweep-%d" % int(time.time()))
    os.makedirs(sweep_dir, exist_ok=True)

    os.environ["SANITIZER_SWEEP_DIR"]  = sweep_dir
    os.environ["SANITIZER_SWEEP_TOOL"] = args.compute_sanitizer

    BIN = os.path.join(TDIR, "compute_sanitizer", "sweep_shim.sh")

    print("[ test.py ] Compute Sanitizer sweep enabled (tool=%s). Results: %s" % (args.compute_sanitizer, sweep_dir))
    print("[ test.py ] Report with: tools/compute_sanitizer/report.py --dir %s" % sweep_dir)

  # -a is unset by default so the two paths can differ: the crack path runs -a 0, the edge path the
  # whole attack set, as their test.sh and test_edge.sh counterparts do.

  if args.attack is None:
    args.attack = "all" if args.edge else "0"

  setup_isolation()

  if not os.path.isfile(BIN):
    die("! no hashcat binary at %s, build it first" % BIN)

  # Ctrl-C persists what has been gathered and prints the total; a -j run hands each worker its share
  # of memory; the reason log opens before any hashcat runs, and its path is exported so -j children
  # write into the one folder. All harmless on a plain serial run, where no folder is made.
  signal.signal(signal.SIGINT, on_sigint)

  # The breadth split shares each card between workers, so each needs its capped slice of the memory;
  # the depth split gives each mode a whole device, so it runs uncapped. Edge and -S use breadth.
  depth = args.jobs > 1 and args.split == "depth" and not args.edge and not args.selftest_all

  if not depth:
    export_worker_mem_shares(args)

  setup_outdir(args)
  atexit.register(finalize_outputs, "completed")

  if args.edge:
    sys.exit(run_edge(args))

  # --bridge runs on its own: it ignores -a and -t and cracks each selected mode's oracle through
  # the Python bridge (mode 73000), so it checks hashcat's parser and candidate handling against the
  # reference implementation rather than the mode's own kernel.
  if args.bridge:
    sys.exit(run_bridge(args))

  # -S runs on its own: it walks every hash-mode hashcat reports rather than the .py oracle set, so
  # it reaches the modes that have no oracle, and it needs no oracle engine (test.sh).

  if args.selftest_all:
    if args.jobs > 1 and not args.selftest_child:
      sys.exit(run_parallel_selftest(args))

    sys.exit(selftest_vector_sweep(args))

  if args.jobs > 1:
    sys.exit(run_parallel_depth(args) if depth else run_parallel(args))

  if args.attack != "all" and (not args.attack.isdigit() or int(args.attack) not in ATTACK_ORDER):
    die("! invalid attack mode: %s" % args.attack)

  if args.attack != "all" and int(args.attack) not in ATTACKS:
    die("! -a %s is not implemented in test.py" % args.attack)

  # Confirm the oracle engine is here before the run: a missing script would exit 2, which is the
  # code the engine uses for "no kernel for this family", so without this a missing engine would
  # be misread as every mode being not applicable.

  if not os.path.isfile(RUNNER):
    die("! no oracle engine at %s" % RUNNER)

  modes    = discover_modes()
  py_modes = set(modes)
  selected = MINIMAL_MODES if args.minimal else select_modes(args.mode, modes)
  targets  = targets_for(args.target)
  widths   = widths_for(args.vector)

  # -g builds a real container/archive and cracks that. On its own it runs every mode it can build;
  # with -m it keeps only the selected ones it can. Selecting none it can build is worth stopping for:
  # the run would otherwise finish clean having generated nothing, which reads like a pass (test.sh).
  if args.generate:
    global GEN_PURE, CONTAINER_PASSWORD, CONTAINER_MASK, CONTAINER_MASK_MID
    global TC_TESTS_DIR, VC_TESTS_DIR, LUKS_TESTS_DIR, LUKS2_TESTS_DIR

    GEN_PURE = args.pure
    selected = [m for m in selected if m in GEN_MODES]

    if not selected:
      die("! -g has no generator for -m %s\n! -g can build: %s"
          % (args.mode, " ".join(str(m) for m in sorted(GEN_MODES))))

    # The generated containers get a password of their own, so a pass cannot come from 'hashcat' being
    # baked into both the volume and the mask (test.sh). The masks follow from it.
    CONTAINER_PASSWORD = gen_password_string()
    CONTAINER_MASK     = container_mask_from_password(CONTAINER_PASSWORD, "last")
    CONTAINER_MASK_MID = container_mask_from_password(CONTAINER_PASSWORD, "first")

    # Ask for root up front, once, if any selected mode needs it, rather than stopping for a prompt an
    # hour into a long run. Refresh the ticket in the background so it does not expire partway through.
    if any(m in GEN_SUDO_MODES for m in selected):
      if subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL).returncode != 0:
        print("> Some selected modes build their container as root, so this run needs sudo. Asking now.")

        if subprocess.run(["sudo", "-v"]).returncode != 0:
          die("! No root, so those modes cannot be generated. Deselect them, or run without -g.")

      import threading

      def _sudo_keepalive():
        while True:
          subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
          time.sleep(60)

      threading.Thread(target=_sudo_keepalive, daemon=True).start()

  skips   = []
  missing = set()

  with tempfile.TemporaryDirectory(prefix="test_py_") as tmp:
    # With -g the container families read the volumes this run builds, not the ones in the tree or
    # fetched from hashcat.net, so point their directories at a per-run location (test.sh).
    if args.generate:
      TC_TESTS_DIR    = os.path.join(tmp, "tc_tests_gen")
      VC_TESTS_DIR    = os.path.join(tmp, "vc_tests_gen")
      LUKS_TESTS_DIR  = os.path.join(tmp, "luks_tests_gen")
      LUKS2_TESTS_DIR = os.path.join(tmp, "luks2_tests_gen")
    for mode in selected:
      # STDOUT (2000) is not a crack: its kernel is empty, so it is tested by a --stdout round trip
      # (test.sh does the same). Handled before the kernel/oracle checks, which do not apply to it.
      if mode == STDOUT_MODE:
        run_stdout_roundtrip(args, tmp)
        continue

      # A container mode's hash is a file, not a generated string, so it has no usable oracle: it
      # runs the container full-test (test.sh truecrypt_test/veracrypt_test/luks*_test) instead. Under
      # -g the volumes are built fresh into the repointed dir first, then that same read path runs.
      if mode in CONTAINER_MODES:
        if args.generate:
          generate_containers(args, mode, tmp)

        run_container_mode(args, mode, tmp)
        continue

      # -g adds a real-archive test (GPG/PKZIP/RAR/7-Zip/PDF/OpenSSH) on top of the mode's oracle,
      # which still runs below (test.sh: -g is in addition to the oracle, not in place of it).
      if args.generate and mode in ARCHIVE_GEN_MODES:
        run_generate_archive(args, mode, tmp)

      # A SELFTEST_MODES member with no .py oracle takes the self-test vector path. test.sh runs it
      # only for a slow mode, in the else branch of its per-width loop (test.sh), so a mode
      # that is not slow prints no line, just as test.sh does. 23800 is the only member and is slow.

      if mode not in py_modes:
        if is_slow(mode):
          run_selftest_normal(args, mode, widths, tmp)

        continue

      pairs = oracle_vectors(mode, not args.pure)

      if pairs is None:
        reason = "no %s kernel for this mode" % ("Pure" if args.pure else "Optimized")

        skips.append((mode, reason))

        print("[ test.py ] [ Type %d ] > Skip : %s" % (mode, reason))

        continue

      file_only = is_file_only(mode)
      pass_only = file_only or mode in NOCHECK_ENCODING

      # PKZIP master key only has a single hash test; a forced multi run is skipped outright
      # (test.sh).

      mode_targets = targets

      if mode == 20510:
        if targets == ["multi"]:
          continue

        mode_targets = ["single"]

      for width in widths:
        opts = base_opts(args) + ["--backend-vector-width", str(width)]

        r = Run(args, mode, pairs, width, opts, mode_targets, file_only, pass_only, tmp)

        for attack in attacks_for(args.attack, mode):
          if attack not in ATTACKS:
            missing.add(attack)

            continue

          ATTACKS[attack](r)

  if missing:
    sys.stderr.write("! not implemented in test.py: -a %s\n"
                     % ", ".join(str(a) for a in sorted(missing)))

  if skips:
    print()
    print("[ test.py ] > %d test(s) did not run in full:" % len(skips))

    for mode, reason in skips:
      print("[ test.py ] [ Type %d ] > Skip : %s" % (mode, reason))

  if args.generate:
    print_gen_summary()

  if CAPPED_MEM_SKIP:
    # A -j child: tell the parent this mode skipped only because its memory share was too small, so it
    # can be re-run without the cap. This outranks ERRORS so the parent re-runs on the whole card and
    # the retry's own exit code, not this capped run's, decides pass or fail.
    sys.exit(MEMSKIP_RC)

  if ERRORS:
    sys.exit(1)


if __name__ == "__main__":
  main()
