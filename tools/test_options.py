#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Runs hashcat with every command line option, alone and in pairs, on a few small base scenarios,
# and sorts each run by what it did: crashed, hung, was rejected at startup, or was accepted. An
# accepted option whose run is identical to the base run has no observable effect there, and an
# accepted pair that behaves like one of its two options alone has one option shadowed by the other.
#
# The option list comes from include/options.def and the sample values from the Example column of
# the help table in src/usage.c, so a new option is swept without editing this file. The options the
# modules register are read off the --help of the build under test. "list" prints the table, "run"
# executes runs and appends them to a JSONL file, "report" classifies one or more JSONL files and
# writes runs.json and REPORT.md.
#
#   ./tools/test_options.py list
#   ./tools/test_options.py run --base bf="-d 1" --phase singles -j 16 --workdir sweep --out sweep.jsonl
#   ./tools/test_options.py run --base bf="-d 1" --phase pairs -j 16 --workdir sweep --out sweep.jsonl
#   ./tools/test_options.py report sweep.jsonl --outdir report/
#   ./tools/test_options.py fixtures DIR     # the input files a reproduction command needs
#
# Every worker runs in its own copy of the build under the work directory, hardlinked where the file
# system allows it and linked again after a rebuild.
#
# With "run --verdict" every run gets HASHCAT_OPTION_DEBUG=1, which makes hashcat print the option
# table's verdict, so a refusal is recorded with the rule that made it. "compare" sets two sweeps side
# by side, an earlier build against a newer one, and lists every run whose verdict changed. It exits
# with 1 when a run crashed or newly hung, a refusal was lost, a run could not be made, or the
# frontend and the library caller verdict of a run differ, so it can gate a change:
#
#   ./tools/test_options.py run --verdict --base show= --phase singles -j 16 --workdir sweep --out new.jsonl
#   ./tools/test_options.py compare --old old.jsonl --new new.jsonl --outdir compare/

import argparse
import collections
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

TDIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TDIR)

# Preprocessor symbols taken as defined when reading the option tables. A default Linux build has
# brain support and is neither Apple nor Windows.
DEFINED = {"WITH_BRAIN"}

# Options that print something and end the run before any attack is set up. They are tested as the
# first option of a pair and never as the second, because the pair would only measure them again.
INFO_ONLY = {"version", "help", "hash-info", "backend-info", "identify", "module-cache-rebuild"}

# Options that hold a global resource or never end by themselves. They run alone, one at a time,
# after everything else, and are left out of the pairs.
EXCLUSIVE = {"brain-server"}

# The sample value for an option is taken from its Example column. These are the options where no
# usable sample can be derived from it: no help entry, an example that names a file which does not
# exist or is too big for the small base scenarios.
OVERRIDES = {
  "workload-profile":    ("4",                        "hidden option, no help entry"),
  "cache-path":          ("{WDIR}/altcache",          "example is an absolute path outside the run"),
  "markov-hcstat2":      ("{TREE}/hashcat.hcstat2",   "needs a valid hcstat2 file"),
  "truecrypt-keyfiles":  ("keyfile.bin",              "needs an existing keyfile"),
  "veracrypt-keyfiles":  ("keyfile.bin",              "needs an existing keyfile"),
  "encrypt-with-pubkey": ("pubkey.pem",               "needs an RSA public key"),
  "separator":           (";",                        "example is the default separator"),
  "skip":                ("10",                       "example is beyond the base keyspace"),
  "limit":               ("100",                      "example is beyond the base keyspace"),
  "increment-min":       ("2",                        "example is longer than the base mask"),
  "increment-max":       ("3",                        "example is longer than the base mask"),
}

TYPE_DEFAULT = {
  "Num":  "1",
  "Str":  "x",
  "File": "file.txt",
  "Dir":  "dir",
  "Char": ":",
  "CS":   "?l?d",
  "Rule": ":",
  "Code": "utf-8",
  "Hex":  "0x2ae611db",
  "Port": "6863",
}

# Families of options that can legitimately leave no trace in a short run on these bases. A run that
# matches its base for one of these is still listed, under the family, rather than as a suspect.
# "periodic" acts on a timer or every N launches, which a run of a second never reaches. "no-input"
# has nothing to act on in these fixtures: the kernel cache is not part of the signature, the
# hcstat2 sample is the default file, and no plain or word needs $HEX[].
FAMILIES = {
  "hwmon":         ["hwmon-disable", "hwmon-temp-abort"],
  "tuning":        ["workload-profile", "kernel-accel", "kernel-loops", "kernel-threads", "spin-damp", "backend-vector-width", "multiply-accel-disable", "hook-threads", "cpu-affinity", "scrypt-tmto", "bitmap-min", "bitmap-max", "backend-devices-virtmulti", "backend-devices-virthost"],
  "timer":         ["status-timer", "outfile-check-timer", "remove-timer", "bypass-delay", "bypass-threshold", "stdin-timeout-abort", "runtime", "metal-compiler-runtime", "brain-server-timer"],
  "mode-specific": ["hex-salt", "eapol-message-pair", "nonce-error-corrections", "keyboard-layout-mapping", "truecrypt-keyfiles", "veracrypt-keyfiles", "veracrypt-pim-start", "veracrypt-pim-stop", "bridge-parameter1", "bridge-parameter2", "bridge-parameter3", "bridge-parameter4", "dynamic-x", "username", "hash-copy"],
  "periodic":      ["status", "pipeline-stats", "restore-disable", "restore-file-path"],
  "no-input":      ["cache-path", "markov-hcstat2", "markov-threshold", "outfile-autohex-disable", "wordlist-autohex-disable", "outfile-check-dir"],
  "quiet-check":   ["force", "self-test-disable", "deprecated-check-disable", "advice-disable", "backend-ignore-cuda", "backend-ignore-hip", "backend-ignore-opencl", "length-sort-disable", "color-cracked"],
}

# Base scenarios. Every one is cheap and deterministic. "opts" are written with long names so an
# option under test that sets the same thing replaces the base value rather than repeating it.
BASES = {
  "bf":       {"opts": [["hash-type", "0"], ["attack-mode", "3"], ["outfile", "out.txt"], ["potfile-path", "pot.txt"]], "pos": ["h2.txt", "?l?l?d"]},
  "dict":     {"opts": [["hash-type", "10"], ["attack-mode", "0"], ["outfile", "out.txt"], ["potfile-path", "pot.txt"]], "pos": ["hs.txt", "words.txt"]},
  "stdin":    {"opts": [["hash-type", "0"], ["attack-mode", "0"], ["outfile", "out.txt"], ["potfile-path", "pot.txt"]], "pos": ["h3.txt"], "stdin": "words.txt"},
  "combi":    {"opts": [["hash-type", "0"], ["attack-mode", "1"], ["outfile", "out.txt"], ["potfile-path", "pot.txt"]], "pos": ["hc.txt", "w1.txt", "w2.txt"]},
  "bench":    {"opts": [["benchmark", None], ["hash-type", "0"]], "pos": []},
  "stdout":   {"opts": [["stdout", None], ["attack-mode", "3"]], "pos": ["?l?d"]},
  "keyspace": {"opts": [["keyspace", None], ["attack-mode", "3"]], "pos": ["?l?l?d"]},
  "show":     {"opts": [["show", None], ["hash-type", "0"], ["potfile-path", "pot.txt"]], "pos": ["h3.txt"], "pot": "pot_show.txt"},
  "left":     {"opts": [["left", None], ["hash-type", "0"], ["potfile-path", "pot.txt"]], "pos": ["h3.txt"], "pot": "pot_show.txt"},
}

WORDS = ["password", "123456", "letmein", "dragon", "monkey", "qwerty", "abc123", "football", "iloveyou", "admin",
         "welcome", "sunshine", "master", "shadow", "hashcat", "trustno1", "princess", "starwars", "baseball", "superman",
         "batman", "charlie", "freedom", "whatever", "michael", "jessica", "hunter2", "secret", "zaq12wsx", "passw0rd",
         "computer", "internet", "summer", "winter", "orange", "banana", "cookie", "pepper", "ginger", "matrix"]

CRASH_PATTERNS = [
  re.compile(r"AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:"),
  re.compile(r"double free|free\(\): invalid|malloc\(\): |corrupted size|stack smashing|buffer overflow detected"),
  re.compile(r"Segmentation fault|Bus error|Illegal instruction|Floating point exception|Aborted \(core"),
]

CRASH_RCS = {132, 133, 134, 135, 136, 137, 139}

# Lines that change from one run to the next for reasons unrelated to the options: clocks, speeds,
# sensors and the interactive prompt, whose repetitions depend on timing.
DROP = re.compile(r"^(Time\.(Started|Estimated)|Started:|Stopped:|Speed\.#|Hardware\.Mon\.#|Approaching final keyspace|Util\.|\* Runtime\.\.\.|\* Speed\.\.\.\.\.:)|\[s\]tatus \[p\]ause")

SUBS = [
  (re.compile(r"Parsing Hashes: \d+/\d+ \([\d.]+%\)\.\.\."), ""),
  (re.compile(r"\(\d+ MB free\)"),                     "(N MB free)"),
  (re.compile(r"\d+/\d+ MB"),                          "N/N MB"),
  (re.compile(r"\(\d+ MB allocatable\)"),              "(N MB allocatable)"),
  (re.compile(r"\d+(\.\d+)? ?(ms|secs?|mins?|hours?)\b"), "N \\2"),
  (re.compile(r"\d+(\.\d+)? ?[kMGTP]?H/s"),            "N H/s"),
  (re.compile(r"Accel:\d+ Loops:\d+ Thr:\d+ Vec:\d+"), "Accel:N Loops:N Thr:N Vec:N"),
  (re.compile(r"\"(time_start|estimated_stop|speed|temp|util|exec_runtime|runtime|fanspeed|corespeed|memoryspeed|power|time_[a-z_]+)\"\s*:\s*-?[\d.]+"), "\"\\1\": N"),
  (re.compile(r"\b(EXEC_RUNTIME|SPEED|TEMP|UTIL|POWER|CORESPEED|MEMORYSPEED|FANSPEED)((\t[\d.:]+)+)"), "\\1\tN"),
  (re.compile(r"expecting at least \d+ base words but only got [\d.]+%"), "expecting at least N base words but only got N%"),
  (re.compile(r"\d{2}:\d{2}:\d{2}"),                   "HH:MM:SS"),
  (re.compile(r"\bpid \d+"),                           "pid N"),
  (re.compile(r"0x[0-9a-f]{10,}"),                     "0xADDR"),
  (re.compile(r"==\d+=="),                             "==PID=="),
]

# The hashcat processes running right now, so an interrupted sweep can stop them. They run in
# sessions of their own, so a Ctrl-C does not reach them.
LIVE_PROCS = set()

LIVE_LOCK = threading.Lock()


def strip_c_comment(line: str) -> str:
  pos = line.find("//")

  if pos == -1: return line

  return line[:pos]


def active_lines(text: str) -> list:
  # Keeps the lines a build with DEFINED would compile. Only the conditional forms the two tables
  # use are understood: #if defined (X), #ifdef X, #ifndef X, #else and #endif.
  out = []
  stack = []

  for line in text.split("\n"):
    s = line.strip()

    m = re.match(r"#\s*(ifdef|ifndef|if)\s+(.*)", s)

    if m:
      names = re.findall(r"defined\s*\(\s*(\w+)\s*\)", m.group(2))

      if m.group(1) != "if": names = [m.group(2).strip()]

      cond = any(n in DEFINED for n in names)

      if m.group(1) == "ifndef": cond = (cond == False)

      stack.append(cond)

      continue

    if s.startswith("#else"):
      stack[-1] = (stack[-1] == False)

      continue

    if s.startswith("#endif"):
      stack.pop()

      continue

    if all(stack) == False: continue

    out.append(line)

  return out


def parse_long_options(root: str) -> list:
  with open(os.path.join(root, "include", "options.def")) as f:
    text = f.read()

  entry = re.compile(r"OPTION\s*\(\s*\w+\s*,\s*\"([^\"]+)\"\s*,\s*([^,]+?)\s*,\s*(\w+)\s*,\s*(no_argument|required_argument|optional_argument)\s*\)")

  out = []

  for line in active_lines(text):
    m = entry.search(strip_c_comment(line))

    if m is None: continue

    letter = m.group(2).strip("'") if m.group(2).startswith("'") else ""

    out.append({"name": m.group(1), "letter": letter, "has_arg": m.group(4) != "no_argument", "idx": m.group(3)})

  # The options the modules register are in no source table, so they are read off --help, which
  # lists every one that is not hidden. Each is its own IDX.
  for name, u in module_help_rows(root).items():
    out.append({"name": name, "letter": "", "has_arg": u["type"] != "", "idx": "MODULE_" + name})

  return out


def usage_rows(lines: list) -> dict:
  out = {}

  for line in lines:
    cols = [c.strip() for c in line.split("|")]

    if len(cols) < 4: continue

    names = re.findall(r"--([a-z0-9-]+)", cols[0])

    if len(names) == 0: continue

    out[names[0]] = {"type": cols[1], "desc": cols[2], "example": cols[3]}

  return out


HELP_ROWS = {}


def help_rows(root: str) -> dict:
  if root in HELP_ROWS: return HELP_ROWS[root]

  binary = os.path.join(root, "hashcat")

  proc = subprocess.run([binary, "--help"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=root, timeout=120)

  text = proc.stdout.decode("utf-8", "replace")

  # the module options are only in a --help that ran to its end
  if (proc.returncode != 0) or (("Usage: hashcat" in text) == False):
    raise RuntimeError("%s --help ended with exit code %d, so the module options cannot be read" % (binary, proc.returncode))

  rows = usage_rows(text.split("\n"))

  HELP_ROWS[root] = rows

  return rows


def usage_table_rows(root: str, active: bool) -> dict:
  with open(os.path.join(root, "src", "usage.c")) as f:
    text = f.read()

  start = text.index("USAGE_BIG_PRE_HASHMODES[]")
  end   = text.index("NULL", start)

  table = text[start:end]

  lines = []

  for line in (active_lines(table) if active == True else table.split("\n")):
    m = re.match(r"\s*\"(.*)\",?\s*$", line)

    if m is None: continue

    lines.append(m.group(1))

  rows = usage_rows(lines)

  return rows


def module_help_rows(root: str) -> dict:
  # the --help rows that usage.c does not have, which are the ones the modules registered
  table = usage_table_rows(root, False)

  out = collections.OrderedDict()

  for name, u in help_rows(root).items():
    if name in table: continue

    out[name] = u

  return out


def parse_usage(root: str) -> dict:
  out = usage_table_rows(root, True)

  for name, u in module_help_rows(root).items(): out[name] = u

  return out


def example_value(example: str) -> str | None:
  # "-h or -hh" style examples give alternatives, the first one is enough. Long names may be
  # abbreviated in the table (--keyb=...), getopt accepts any unique prefix.
  if example == "": return None

  first = example.split(" or ")[0]

  try:
    tokens = shlex.split(first)
  except ValueError:
    return None

  for i, tok in enumerate(tokens):
    if tok.startswith("-") == False: continue

    if "=" in tok: return tok.split("=", 1)[1]

    if i + 1 < len(tokens): return tokens[i + 1]

    return None

  return None


def enumerate_options(root: str) -> list:
  longs = parse_long_options(root)
  usage = parse_usage(root)

  # Several names can share one IDX (aliases). The first name with a help entry stands for the
  # group, the others are recorded as aliases and not swept twice.
  by_idx = collections.OrderedDict()

  for o in longs:
    by_idx.setdefault(o["idx"], []).append(o)

  options = []

  for idx, group in by_idx.items():
    # The lead is the first name with a help entry that is not described as an alias.
    lead = group[0]

    u = None

    for o in group:
      if (o["name"] in usage) == False: continue

      if usage[o["name"]]["desc"].startswith("Alias"): continue

      lead = o
      u    = usage[o["name"]]

      break

    opt = {
      "name":    lead["name"],
      "idx":     idx,
      "has_arg": lead["has_arg"],
      "aliases": [o["name"] for o in group if o["name"] != lead["name"]],
      "hidden":  u is None,
      "type":    "" if u is None else u["type"],
      "example": "" if u is None else u["example"],
      "value":   None,
      "source":  "flag",
      "why":     "",
    }

    if lead["has_arg"] == True:
      if lead["name"] in OVERRIDES:
        opt["value"]  = OVERRIDES[lead["name"]][0]
        opt["source"] = "override"
        opt["why"]    = OVERRIDES[lead["name"]][1]
      else:
        v = example_value(opt["example"])

        if v is None:
          opt["value"]  = TYPE_DEFAULT.get(opt["type"], "1")
          opt["source"] = "type-default"
        else:
          opt["value"]  = v
          opt["source"] = "example"

        # An input file named by the example is used from the tree when it ships there.
        if opt["type"] in ("File", "Dir"):
          if opt["value"].startswith("/"): opt["value"] = os.path.basename(opt["value"])

          if os.path.exists(os.path.join(root, opt["value"])): opt["value"] = "{TREE}/" + opt["value"]

    options.append(opt)

  return options


def option_family(name: str) -> str:
  for fam, names in FAMILIES.items():
    if name in names: return fam

  if name.startswith("brain-"): return "brain"

  return ""


def md5_hex(s: str) -> str:
  digest = hashlib.md5(s.encode()).hexdigest()

  return digest


def write_fixtures(fdir: str) -> None:
  os.makedirs(fdir, exist_ok=True)

  def put(name: str, lines: list) -> None:
    with open(os.path.join(fdir, name), "w") as f:
      f.write("\n".join(lines) + "\n")

  put("words.txt", WORDS)
  put("h2.txt",    [md5_hex("ab1"), md5_hex("zz9")])
  put("h3.txt",    [md5_hex("letmein"), md5_hex("hashcat"), md5_hex("notinthelist")])
  put("hs.txt",    [md5_hex("dragon" + "s1") + ":s1", md5_hex("matrix" + "ab") + ":ab", md5_hex("nothere" + "zz") + ":zz"])
  put("w1.txt",    ["admin", "root", "pass"])
  put("w2.txt",    ["123", "word", "!"])
  put("hc.txt",    [md5_hex("admin123"), md5_hex("rootword"), md5_hex("nomatch")])
  put("pot_show.txt", [md5_hex("letmein") + ":letmein", md5_hex("hashcat") + ":hashcat"])
  put("file.txt",  ["x"])

  with open(os.path.join(fdir, "keyfile.bin"), "wb") as f:
    f.write(bytes(range(64)))

  pem = os.path.join(fdir, "pubkey.pem")

  if os.path.exists(pem) == False:
    key = os.path.join(fdir, "privkey.pem")

    try:
      subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", key], check=True, capture_output=True)
      subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-out", pem], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
      put("pubkey.pem", ["not a key"])

    if os.path.exists(key): os.unlink(key)


def sync_file(s: str, d: str) -> None:
  # A hardlink where the file system allows one and a copy where it does not. A file a rebuild has
  # replaced is a new inode, so the old link is dropped and made again.
  if os.path.lexists(d):
    st_s = os.lstat(s)
    st_d = os.lstat(d)

    if (st_s.st_dev == st_d.st_dev) and (st_s.st_ino == st_d.st_ino): return

    # a copy made where no link could be is kept while it matches the build's file
    if (st_s.st_size == st_d.st_size) and (st_s.st_mtime_ns == st_d.st_mtime_ns): return

    os.unlink(d)

  try:
    os.link(s, d, follow_symlinks=False)
  except OSError:
    shutil.copy2(s, d, follow_symlinks=False)


def sync_dir(s: str, d: str) -> None:
  os.makedirs(d, exist_ok=True)

  for name in os.listdir(s):
    sp = os.path.join(s, name)
    dp = os.path.join(d, name)

    if (os.path.isdir(sp) == True) and (os.path.islink(sp) == False):
      sync_dir(sp, dp)
    else:
      sync_file(sp, dp)


def link_tree(src: str, dst: str) -> None:
  # A hardlinked copy of the build tree, so every worker has its own install directory. A build
  # that is not installed keeps its session, restore, log, potfile and kernel cache files next to
  # the binary, and those must not be shared between parallel runs. A work directory inside the
  # build is left out, or it would be copied into itself.
  skip_top = {"obj", "cache", "kernels", "src", "deps", "docs", ".git"}

  skip_ext = (".log", ".restore", ".potfile", ".dictstat2", ".pid", ".induct", ".outfiles")

  os.makedirs(dst, exist_ok=True)

  dst_real = os.path.realpath(dst)

  for name in os.listdir(src):
    if name in skip_top: continue

    if name.endswith(skip_ext): continue

    s = os.path.join(src, name)
    d = os.path.join(dst, name)

    s_real = os.path.realpath(s)

    if (dst_real == s_real) or (dst_real.startswith(s_real + os.sep) == True): continue

    if (os.path.isdir(s) == True) and (os.path.islink(s) == False):
      sync_dir(s, d)
    else:
      sync_file(s, d)


def normalise(text: str, ctx: dict) -> str:
  for key in ("RUN", "TREE", "WDIR"):
    text = text.replace(ctx[key], "<" + key + ">")

  text = re.sub(r"\b" + re.escape(ctx["SES"]) + r"\b", "<SES>", text)

  out = []

  for raw in text.split("\n"):
    segs = [s for s in raw.split("\r") if s.strip() != ""]

    if len(segs) == 0: continue

    line = segs[-1].rstrip()

    if DROP.search(line): continue

    for pat, rep in SUBS:
      line = pat.sub(rep, line)

    out.append(line)

  return "\n".join(out)


def read_text(path: str, ctx: dict) -> str:
  # Lines are sorted: several cracks found in one batch reach the outfile and the potfile in an
  # order that changes from run to run.
  with open(path, "rb") as f:
    data = f.read(65536)

  if b"\0" in data: return "<binary>"

  try:
    s = data.decode("utf-8")
  except UnicodeDecodeError:
    return "<binary>"

  lines = normalise(s, ctx).split("\n")

  return "\n".join(sorted(lines))


def snapshot(path: str) -> dict:
  out = {}

  for dirpath, dirnames, filenames in os.walk(path):
    for fn in filenames:
      full = os.path.join(dirpath, fn)

      try:
        st = os.stat(full)
      except OSError:
        continue

      out[os.path.relpath(full, path)] = (st.st_size, st.st_mtime_ns)

  return out


def crash_lines(text: str) -> list:
  # The sanitizer and glibc error lines, each followed by the stack frames printed under it.
  out = []

  in_stack = False

  for line in text.split("\n"):
    hit = any(pat.search(line) for pat in CRASH_PATTERNS)

    if hit == True:
      out.append(line.strip())

      in_stack = True

      continue

    if (in_stack == True) and (re.match(r"\s+#\d+ 0x", line)):
      out.append(line.strip())

      continue

    # AddressSanitizer prints "==pid==..." detail lines between the error and its stack.
    if (in_stack == True) and line.startswith("=="): continue

    if line.strip() != "": in_stack = False

  return out[:60]


def crash_reports(lines: list, rc: int, timed_out: bool) -> list:
  # One short signature per distinct fault in a run, so the same fault reached from different
  # command lines is reported once. A sanitizer fault is named by its first frame inside src/.
  out = []

  i = 0

  while i < len(lines):
    line = lines[i]

    m = re.search(r"(src/\S+?):(\d+):\d+: runtime error: (.*)", line)

    if m:
      msg = re.sub(r"0x[0-9a-f]+", "ADDR", m.group(3))

      msg = re.sub(r"\d+", "N", msg)[:100]

      out.append("UBSan %s:%s %s" % (m.group(1), m.group(2), msg))

      i += 1

      continue

    m = re.search(r"ERROR: (AddressSanitizer|LeakSanitizer): (.+?)(?: on | in |$)", line)

    if m:
      where = ""

      j = i + 1

      # The first frame in hashcat's own code, past the sanitizer runtime and the hcmalloc wrappers.
      while (j < len(lines)) and (lines[j].startswith("#") == True):
        f = re.search(r"in (\S+) (\S*src/\S+?):(\d+)", lines[j])

        if (f) and (("libsanitizer" in f.group(2)) or (f.group(2).endswith("src/memory.c") == True)): f = None

        if f:
          where = " in %s %s:%s" % (f.group(1), f.group(2)[f.group(2).index("src/"):], f.group(3))

          break

        j += 1

      out.append("%s %s%s" % (m.group(1), m.group(2), where))

      i += 1

      continue

    m = re.search(r"double free|free\(\): invalid \w+|malloc\(\): [\w ]+|corrupted size[\w ]*|stack smashing|buffer overflow detected", line)

    if m: out.append("glibc " + m.group(0))

    i += 1

  if (len(out) == 0) and (rc < 0): out.append("signal %d" % -rc)

  if (len(out) == 0) and (rc in CRASH_RCS): out.append("rc %d" % rc)

  if timed_out == True: out = ["timeout"]

  return sorted(set(out))


def error_message(err: str, out: str) -> str:
  # hashcat writes its errors to stderr, the first line there is the message. Without one, the
  # first line of stdout that reads like an error.
  lines = [x.strip() for x in err.split("\n") if x.strip() != ""]

  if len(lines) > 0: return lines[0]

  for line in out.split("\n"):
    x = line.strip()

    if re.search(r"(?i)\b(error|invalid|not allowed|requires|cannot|must|failed|not supported)\b", x): return x

  return ""


def repro(argv: list) -> str:
  # A command line to paste in the build directory, after "fixtures DIR" has written the inputs
  # there. The per-worker session name and paths are replaced by fixed ones.
  out = []

  for a in argv:
    a = a.replace("<SES>", "sweep").replace("<TREE>/", "").replace("<WDIR>/", "").replace("<RUN>/", "")

    out.append(shlex.quote(a))

  line = "./hashcat " + " ".join(out)

  return line


def job_key(base: str, opts: list) -> str:
  key = base + "|" + "+".join(o["name"] for o in opts)

  return key


def stable_key(key: str) -> str:
  # A pair is keyed by its two options in the order they were enumerated, which moves when an option
  # is added or moves into a module, so a comparison sorts the two names.
  base, _, opts = key.partition("|")

  key = base + "|" + "+".join(sorted(opts.split("+")))

  return key


class Worker:
  def __init__(self, idx: int, args: argparse.Namespace):
    self.idx     = idx
    self.args    = args
    self.wdir    = os.path.join(args.workdir, "w%02d" % idx)
    self.tree    = os.path.join(self.wdir, "tree")
    self.rundir  = os.path.join(self.wdir, "run")
    self.fdir    = os.path.join(args.workdir, "fixtures")
    self.session = "osw%s%02d" % (args.label, idx)

    link_tree(args.hashcat_root, self.tree)

    os.makedirs(os.path.join(self.wdir, "altcache"), exist_ok=True)

    self.tree_base = set(os.listdir(self.tree))

  def ctx(self) -> dict:
    return {"RUN": self.rundir, "TREE": self.tree, "WDIR": self.wdir, "SES": self.session}

  def expand(self, s: str) -> str:
    out = s.replace("{TREE}", self.tree).replace("{WDIR}", self.wdir)

    return out

  def build(self, base: str, opts: list) -> list:
    spec = BASES[base]

    dev = self.args.bases[base]

    tested = {o["idx"] for o in opts}

    argv = [os.path.join(self.tree, "hashcat")]

    harness = [[n, v] for n, v in spec["opts"]] + dev + [["session", self.session]]

    for name, val in harness:
      idx = self.args.name_to_idx.get(name)

      if idx in tested: continue

      argv.append("--" + name)

      if val is None: continue

      argv.append(val)

    for o in opts:
      if o["has_arg"] == True:
        argv.append("--" + o["name"] + "=" + self.expand(o["value"]))
      else:
        argv.append("--" + o["name"])

    argv += spec["pos"]

    return argv

  def duplicate(self, base: str, opts: list) -> bool:
    # A flag the base already passes, tested again, measures nothing.
    spec = BASES[base]

    for name, val in spec["opts"]:
      if val is None:
        for o in opts:
          if self.args.name_to_idx.get(name) == o["idx"]: return True

    return False

  def prepare_rundir(self, base: str) -> dict:
    shutil.rmtree(self.rundir, ignore_errors=True)

    os.makedirs(self.rundir)

    for fn in os.listdir(self.fdir):
      shutil.copy(os.path.join(self.fdir, fn), os.path.join(self.rundir, fn))

    spec = BASES[base]

    if "pot" in spec: shutil.copy(os.path.join(self.fdir, spec["pot"]), os.path.join(self.rundir, "pot.txt"))

    before = snapshot(self.rundir)

    return before

  def clean_tree(self) -> list:
    # The compiled kernels stay, everything else a run left in the cache goes: the wordlist seek
    # database turns "Dictionary cache built" into "Dictionary cache hit" for the next run. The module
    # option cache stays as well, so that the runs after the first read their options from it, as
    # every start but the first does.
    for cache in (os.path.join(self.tree, "cache"), os.path.join(self.wdir, "altcache")):
      if os.path.isdir(cache) == False: continue

      for name in os.listdir(cache):
        if name == "kernels": continue

        if (name.startswith("module_options.") == True) and (name.endswith(".cache") == True): continue

        p = os.path.join(cache, name)

        if os.path.isdir(p) == True:
          shutil.rmtree(p, ignore_errors=True)
        else:
          os.unlink(p)

    created = []

    for name in sorted(os.listdir(self.tree)):
      if name in self.tree_base: continue

      if name == "cache": continue

      created.append(name)

      p = os.path.join(self.tree, name)

      if (os.path.isdir(p) == True) and (os.path.islink(p) == False):
        shutil.rmtree(p, ignore_errors=True)
      else:
        os.unlink(p)

    return created

  def run(self, job: dict) -> dict:
    base = job["base"]
    opts = job["opts"]

    key = job_key(base, opts)

    if job["kind"] == "base": key += "#%d" % job["rep"]

    rec = {"key": key, "label": self.args.label, "base": base, "kind": job["kind"], "opts": [[o["name"], o["value"]] for o in opts], "worker": self.idx}

    if job.get("confirm") == True: rec["confirm"] = True

    if self.args.sanitizer == True: rec["sanitizer"] = True

    if self.duplicate(base, opts):
      rec["class_hint"] = "duplicate"

      return rec

    argv = self.build(base, opts)

    before = self.prepare_rundir(base)

    self.clean_tree()

    spec = BASES[base]

    stdin_data = None

    if "stdin" in spec:
      with open(os.path.join(self.fdir, spec["stdin"]), "rb") as f:
        stdin_data = f.read()

    env = dict(os.environ)

    env.pop("POSIXLY_CORRECT", None)

    env.pop("HASHCAT_OPTION_DEBUG", None)

    if self.args.verdict == True: env["HASHCAT_OPTION_DEBUG"] = "1"

    env["ASAN_OPTIONS"]  = "detect_leaks=0:abort_on_error=0:protect_shadow_gap=0:print_summary=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1"

    # Every run sizes itself to the whole card and host, so parallel runs on one device need a share
    # each, the way tools/test.py export_worker_mem_shares hands it out.
    if self.args.device_mem_limit > 0: env["HASHCAT_DEVICE_MEM_LIMIT"] = str(self.args.device_mem_limit)
    if self.args.host_mem_limit   > 0: env["HASHCAT_HOST_MEM_LIMIT"]   = str(self.args.host_mem_limit)

    t0 = time.time()

    stdin_mode = subprocess.DEVNULL if stdin_data is None else subprocess.PIPE

    proc = subprocess.Popen(argv, cwd=self.rundir, stdin=stdin_mode, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)

    with LIVE_LOCK:
      LIVE_PROCS.add(proc)

    timed_out = False

    try:
      out, err = proc.communicate(stdin_data, timeout=self.args.timeout)
    except subprocess.TimeoutExpired:
      timed_out = True

      try:
        os.killpg(proc.pid, signal.SIGKILL)
      except OSError:
        pass

      out, err = proc.communicate()

    with LIVE_LOCK:
      LIVE_PROCS.discard(proc)

    elapsed = time.time() - t0

    out_s = out.decode("utf-8", "replace")
    err_s = err.decode("utf-8", "replace")

    # The validator's lines are taken out of stderr, so the message and the signatures are the ones a
    # run without the variable produces.
    verdicts = []
    derive   = []
    structs  = []

    if self.args.verdict == True:
      rest = []

      for line in err_s.split("\n"):
        if line.startswith("OPTION-DERIVE "):
          derive.append(parse_verdict_line(line))
        elif line.startswith("OPTION-VERDICT "):
          verdicts.append(parse_verdict_line(line))
        elif line.startswith("OPTION-STRUCT "):
          structs.append(parse_verdict_line(line))
        elif line.startswith("OPTION-CACHE "):
          # where the module options came from, which depends on the runs before this one
          continue
        else:
          rest.append(line)

      err_s = "\n".join(rest)

    ctx = self.ctx()

    after = snapshot(self.rundir)

    files = {}

    for name in sorted(after):
      if before.get(name) == after[name]: continue

      files[normalise(name, ctx)] = read_text(os.path.join(self.rundir, name), ctx)

    for name in sorted(before):
      if name in after: continue

      files[name] = "<deleted>"

    tree_created = [normalise(n, ctx) for n in self.clean_tree()]

    out_n = normalise(out_s, ctx)
    err_n = normalise(err_s, ctx)

    sig_parts = [proc.returncode, out_n, err_n, files, tree_created]

    rec["argv"]      = [normalise(a, ctx) for a in argv[1:]]
    rec["repro"]     = repro(rec["argv"])
    rec["rc"]        = proc.returncode
    rec["timeout"]   = timed_out
    rec["elapsed"]   = round(elapsed, 2)
    rec["sig"]       = hashlib.sha1(json.dumps(sig_parts, sort_keys=True).encode()).hexdigest()[:16]
    rec["sig_out"]   = hashlib.sha1(out_n.encode()).hexdigest()[:12]
    rec["sig_err"]   = hashlib.sha1(err_n.encode()).hexdigest()[:12]
    rec["sig_files"] = hashlib.sha1(json.dumps([files, tree_created], sort_keys=True).encode()).hexdigest()[:12]
    rec["msg"]       = error_message(err_n, out_n)
    rec["crash"]     = crash_lines(out_s + "\n" + err_s)
    rec["reports"]   = crash_reports(rec["crash"], proc.returncode, timed_out)

    if self.args.verdict == True:
      rec["verdict"]  = verdicts[-1] if len(verdicts) > 0 else None
      rec["verdicts"] = verdicts
      rec["derive"]   = derive

      # the static verdict a library caller would get for the same settings, read off the struct
      rec["struct"]  = structs[-1] if len(structs) > 0 else None

    rec["usage"] = "Usage: hashcat" in out_s

    keep = (job["kind"] != "pair") or timed_out or (len(rec["crash"]) > 0) or (proc.returncode < 0) or (proc.returncode in CRASH_RCS)

    if keep == True:
      rec["out_n"] = out_n
      rec["err_n"] = err_n
      rec["files"] = files
      rec["tree"]  = tree_created

      logdir = os.path.join(self.args.logdir, self.args.label)

      os.makedirs(logdir, exist_ok=True)

      logname = re.sub(r"[^A-Za-z0-9_.+|-]", "_", rec["key"]).replace("|", "__") + ".log.gz"

      rec["log"] = os.path.join(logdir, logname)

      with gzip.open(rec["log"], "wt") as f:
        f.write("argv: " + " ".join(shlex.quote(a) for a in argv) + "\ncwd: " + self.rundir + "\nrc: " + str(proc.returncode) + " timeout: " + str(timed_out) + "\n--- stdout\n" + out_s + "\n--- stderr\n" + err_s)

    return rec


def make_jobs(args: argparse.Namespace, options: list, previous: list) -> list:
  jobs = []

  done_singles = {}

  for r in previous:
    if r.get("kind") == "single": done_singles[r["key"]] = "timeout" if r.get("timeout") == True else "done"

  by_name = {o["name"]: o for o in options}

  # A timeout is only a suspect until it repeats: the confirm phase runs every timed out key again,
  # one at a time, under the --timeout given for it.
  if args.phase == "confirm":
    latest = {}

    for r in previous:
      if r.get("kind") in ("single", "pair"): latest[r["key"]] = r

    for key, r in latest.items():
      if r.get("timeout") != True: continue

      if r.get("confirm") == True: continue

      if r["opts"][0][0] in EXCLUSIVE: continue

      if (r["base"] in args.bases) == False: continue

      jobs.append({"base": r["base"], "opts": [by_name[n] for n, v in r["opts"]], "kind": r["kind"], "exclusive": True, "confirm": True})

    return jobs

  sweep = [o for o in options if (o["name"] in args.exclude_set) == False]

  for base in args.bases:
    if args.phase in ("base", "all"):
      for r in range(args.base_repeats):
        jobs.append({"base": base, "opts": [], "kind": "base", "rep": r})

    if args.phase in ("singles", "all"):
      for o in sweep:
        if o["name"] in EXCLUSIVE: continue

        jobs.append({"base": base, "opts": [o], "kind": "single"})

    if args.phase in ("pairs", "all"):
      pair_opts = [o for o in sweep if (o["name"] in EXCLUSIVE) == False]

      for i in range(len(pair_opts)):
        for j in range(i + 1, len(pair_opts)):
          a = pair_opts[i]
          b = pair_opts[j]

          if (a["name"] in INFO_ONLY) and (b["name"] in INFO_ONLY): continue

          if b["name"] in INFO_ONLY: a, b = b, a

          # A single that already ran into the timeout on this base would only time out again.
          if done_singles.get(job_key(base, [a])) == "timeout": continue
          if done_singles.get(job_key(base, [b])) == "timeout": continue

          jobs.append({"base": base, "opts": [a, b], "kind": "pair"})

    if args.phase in ("exclusive", "all"):
      for o in sweep:
        if o["name"] in EXCLUSIVE: jobs.append({"base": base, "opts": [o], "kind": "single", "exclusive": True})

  return jobs


def load_jsonl(paths: list) -> list:
  out = []

  for p in paths:
    if os.path.exists(p) == False: continue

    with open(p) as f:
      for line in f:
        line = line.strip()

        if line == "": continue

        try:
          out.append(json.loads(line))
        except json.JSONDecodeError:
          continue

  return out


def cmd_list(args: argparse.Namespace) -> int:
  options = enumerate_options(args.hashcat_root)

  if args.json == True:
    print(json.dumps(options, indent=1))

    return 0

  for o in options:
    tags = []

    if o["hidden"] == True: tags.append("hidden")
    if o["name"] in INFO_ONLY: tags.append("info-only")
    if o["name"] in EXCLUSIVE: tags.append("exclusive")
    if len(o["aliases"]) > 0: tags.append("aliases=" + ",".join(o["aliases"]))

    val = "" if o["value"] is None else o["value"]

    print("%-28s %-5s %-24s %-13s %s" % (o["name"], o["type"], val, o["source"], " ".join(tags)))

  print()
  print("%d options, %d with an override, %d with a type default" % (len(options), sum(1 for o in options if o["source"] == "override"), sum(1 for o in options if o["source"] == "type-default")))

  return 0


def cmd_fixtures(args: argparse.Namespace) -> int:
  write_fixtures(args.dir)

  for name in sorted(os.listdir(args.dir)):
    print(os.path.join(args.dir, name))

  return 0


def cmd_run(args: argparse.Namespace) -> int:
  options = enumerate_options(args.hashcat_root)

  longs = parse_long_options(args.hashcat_root)

  args.name_to_idx = {}

  for o in longs:
    args.name_to_idx[o["name"]] = o["idx"]

  by_letter = {o["letter"]: o for o in longs if o["letter"] != ""}
  by_name   = {o["name"]: o for o in longs}

  args.exclude_set = set(args.exclude)

  bases = collections.OrderedDict()

  for spec in args.base:
    name, _, dev = spec.partition("=")

    if (name in BASES) == False:
      print("unknown base %s, known: %s" % (name, " ".join(BASES)), file=sys.stderr)

      return 2

    toks = shlex.split(dev)

    pairs = []

    i = 0

    # "--name value", "--name=value", "-x value" and "-xvalue", each read as the option takes it
    while i < len(toks):
      tok = toks[i]

      opt = None
      val = None

      inline = False

      if tok.startswith("--") == True:
        opt_name, eq, val = tok[2:].partition("=")

        opt = by_name.get(opt_name)

        inline = (eq == "=")
      elif (tok.startswith("-") == True) and (len(tok) >= 2):
        opt = by_letter.get(tok[1])

        inline = (len(tok) > 2)

        val = tok[2:]

      if opt is None:
        print("--base %s: %s is not an option of this build" % (name, tok), file=sys.stderr)

        return 2

      i += 1

      if opt["has_arg"] == False:
        pairs.append([opt["name"], None])

        continue

      if inline == False:
        if i >= len(toks):
          print("--base %s: %s needs a value" % (name, tok), file=sys.stderr)

          return 2

        val = toks[i]

        i += 1

      pairs.append([opt["name"], val])

    bases[name] = pairs

  args.bases = bases

  # hashcat runs from a directory inside the work directory, so every path into it has to be absolute
  args.workdir = os.path.abspath(args.workdir)

  os.makedirs(args.workdir, exist_ok=True)

  if args.logdir is None: args.logdir = os.path.join(args.workdir, "logs")

  write_fixtures(os.path.join(args.workdir, "fixtures"))

  previous = load_jsonl([args.out])

  done = {r["key"] for r in previous if ("harness_error" in r) == False}

  jobs = make_jobs(args, options, previous)

  todo = [j for j in jobs if (j["kind"] == "base") or (j.get("confirm") == True) or ((job_key(j["base"], j["opts"]) in done) == False)]

  # Interleave the bases, so parallel runs spread over the devices the bases are bound to rather
  # than all landing on one of them.
  per_base = collections.OrderedDict()

  for j in todo:
    per_base.setdefault(j["base"], []).append(j)

  todo = []

  queues = list(per_base.values())

  while len(queues) > 0:
    for q in queues:
      todo.append(q.pop(0))

    queues = [q for q in queues if len(q) > 0]

  # A sanitizer pass only needs the runs a release build accepted, the rejected ones never get past
  # the option checks.
  if isinstance(args.keys_from, str):
    with open(args.keys_from) as f:
      wanted = set(json.load(f))

    todo = [j for j in todo if (j["kind"] == "base") or (job_key(j["base"], j["opts"]) in wanted)]

  if args.limit > 0: todo = todo[:args.limit]

  exclusive = [j for j in todo if j.get("exclusive") == True]
  parallel  = [j for j in todo if j.get("exclusive") != True]

  print("%d jobs, %d left, %d workers" % (len(jobs), len(todo), args.jobs), flush=True)

  workers = [Worker(i, args) for i in range(args.jobs)]

  free = list(range(args.jobs))

  free_lock = threading.Lock()
  out_lock  = threading.Lock()

  progress = {"n": 0, "t0": time.time()}

  with open(args.out, "a") as outf:
    def execute(job: dict) -> None:
      with free_lock:
        wi = free.pop()

      try:
        rec = workers[wi].run(job)
      except Exception as e:
        rec = {"key": job_key(job["base"], job["opts"]), "label": args.label, "base": job["base"], "kind": job["kind"], "opts": [[o["name"], o["value"]] for o in job["opts"]], "harness_error": repr(e)}
      finally:
        with free_lock:
          free.append(wi)

      with out_lock:
        outf.write(json.dumps(rec) + "\n")
        outf.flush()

        progress["n"] += 1

        if (progress["n"] % 200) == 0:
          rate = progress["n"] / max(1.0, time.time() - progress["t0"])

          print("%d/%d done, %.1f runs/s" % (progress["n"], len(todo), rate), flush=True)

    pool = ThreadPoolExecutor(max_workers=args.jobs)

    try:
      list(pool.map(execute, parallel))

      for job in exclusive:
        execute(job)
    except KeyboardInterrupt:
      # The queued runs are dropped and the running ones killed, which ends them at once. Their
      # records and every earlier one are kept, and a resume of the same --out continues from there.
      pool.shutdown(wait=False, cancel_futures=True)

      with LIVE_LOCK:
        for proc in LIVE_PROCS:
          try:
            os.killpg(proc.pid, signal.SIGKILL)
          except OSError:
            pass

      pool.shutdown(wait=True)

      print("interrupted after %d runs" % progress["n"], file=sys.stderr, flush=True)

      return 130

    pool.shutdown(wait=True)

  print("ALLDONE %d runs in %d s" % (progress["n"], time.time() - progress["t0"]), flush=True)

  return 0


def harness_options(base_rec: dict) -> set:
  # The long options the base command line passes itself. An option under test that is one of them
  # replaces the base value, so a run identical to the base shows nothing about the option.
  names = {a[2:] for a in base_rec.get("argv", []) if a.startswith("--")}

  return names


# The exits that refuse a run: -1, and the two codes that refine it, -2 for the attack command and -12
# for the task. They wrap to 255, 254 and 244.

REFUSED_RC = (255, 254, 244)


def basic_class(r: dict) -> str:
  if "harness_error" in r: return "harness-error"
  if r.get("class_hint") == "duplicate": return "duplicate"
  if r.get("timeout") == True: return "hang"
  if len(r.get("reports", [])) > 0: return "crash"
  if r["rc"] in REFUSED_RC: return "rejected"
  if ((r["rc"] >= 245) and (r["rc"] <= 253)) or (r["rc"] == 243): return "failed"

  return None


def classify(records: list) -> dict:
  # Base signature per (label, base): the most common one among the base repetitions.
  base_runs = collections.defaultdict(list)

  for r in records:
    if (r.get("kind") == "base") and ("sig" in r): base_runs[(r["label"], r["base"])].append(r)

  base_sig = {}

  for k, runs in base_runs.items():
    c = collections.Counter(x["sig"] for x in runs)

    sig = c.most_common(1)[0][0]

    ref = [x for x in runs if x["sig"] == sig][0]

    base_sig[k] = {"sig": sig, "rc": ref["rc"], "variants": len(c), "runs": len(runs), "ref": ref, "all": runs, "harness": harness_options(ref)}

  for r in records:
    r["class"] = basic_class(r)

    if r.get("kind") == "base": r["class"] = r["class"] or "base"

  # A run that crashed, hung or was rejected keeps that class. The rest are compared with the base
  # and, for a pair, with its two singles.
  singles = {}

  for r in records:
    if r["kind"] != "single": continue

    singles[(r["label"], r["base"], r["opts"][0][0])] = r

    if isinstance(r["class"], str): continue

    b = base_sig.get((r["label"], r["base"]))

    if b is None:
      r["class"] = "no-base"

      continue

    r["class"] = "ok"

    if (r["rc"] == b["rc"]) and (r["sig"] == b["sig"]): r["class"] = "ignored-single"

  for r in records:
    if r["kind"] != "pair": continue

    if isinstance(r["class"], str): continue

    b = base_sig.get((r["label"], r["base"]))

    sa = singles.get((r["label"], r["base"], r["opts"][0][0]))
    sb = singles.get((r["label"], r["base"], r["opts"][1][0]))

    r["class"] = "ok"

    if (b is None) or (sa is None) or (sb is None): continue

    if (sa["class"] != "ok") or (sb["class"] != "ok"): continue

    if r["sig"] == sa["sig"]:
      r["class"]    = "ignored-in-pair"
      r["shadowed"] = r["opts"][1][0]
      r["by"]       = r["opts"][0][0]
    elif r["sig"] == sb["sig"]:
      r["class"]    = "ignored-in-pair"
      r["shadowed"] = r["opts"][0][0]
      r["by"]       = r["opts"][1][0]
    elif r["sig"] == b["sig"]:
      r["class"]    = "ignored-in-pair"
      r["shadowed"] = "both"
      r["by"]       = "+".join(o[0] for o in r["opts"])

  return base_sig


def run_text(r: dict) -> str:
  parts = [r.get("out_n", ""), "--- stderr", r.get("err_n", "")]

  for name, content in sorted(r.get("files", {}).items()):
    parts.append("--- file " + name)
    parts.append(content)

  parts.append("--- created in tree: " + " ".join(r.get("tree", [])))

  text = "\n".join(parts)

  return text


def describe_diff(a: str, b: str, limit: int = 6) -> list:
  la = a.split("\n")
  lb = b.split("\n")

  sa = set(la)
  sb = set(lb)

  out = ["- " + x for x in la if (x in sb) == False][:limit]
  out += ["+ " + x for x in lb if (x in sa) == False][:limit]

  return out


def cmd_report(args: argparse.Namespace) -> int:
  records = load_jsonl(args.jsonl)

  # A key that ran more than once (a resumed run) keeps its last record.
  latest = collections.OrderedDict()

  bases_only = []

  for r in records:
    if r.get("kind") == "base":
      bases_only.append(r)

      continue

    k = (r["label"], r["key"])

    if (r.get("confirm") == True) and (k in latest): r["first_elapsed"] = latest[k].get("elapsed")

    latest[k] = r

  records = bases_only + list(latest.values())

  # Repro lines and fault signatures are derived again, so a report reflects the current rules for
  # both without running anything.
  for r in records:
    if "argv" in r: r["repro"] = repro(r["argv"])

    if "crash" in r: r["reports"] = crash_reports(r["crash"], r["rc"], r["timeout"])

  base_sig = classify(records)

  os.makedirs(args.outdir, exist_ok=True)

  options = enumerate_options(args.hashcat_root)

  opt_by_name = {o["name"]: o for o in options}

  counts = collections.Counter((r["label"], r["kind"], r["class"]) for r in records)

  # A sanitizer build reports faults that a release build passes through silently, and it changes
  # the output with them, so its runs only count for crashes and hangs.
  san_labels = {r["label"] for r in records if r.get("sanitizer") == True}

  plain = [r for r in records if (r["label"] in san_labels) == False]

  md = []

  md.append("# Option combination sweep")
  md.append("")
  md.append("Generated by tools/test_options.py report from %d runs." % len(records))
  md.append("")
  md.append("## Options")
  md.append("")
  md.append("%d options enumerated from include/options.def and the module options in --help (aliases folded by IDX), %d hidden from --help." % (len(options), sum(1 for o in options if o["hidden"])))
  md.append("")
  md.append("| option | type | sample | source | note |")
  md.append("|---|---|---|---|---|")

  for o in options:
    note = o["why"]

    if len(o["aliases"]) > 0: note = (note + " aliases: " + ", ".join(o["aliases"])).strip()
    if o["hidden"] == True: note = (note + " hidden").strip()
    if o["name"] in INFO_ONLY: note = (note + " info-only").strip()
    if o["name"] in EXCLUSIVE: note = (note + " exclusive").strip()

    md.append("| --%s | %s | %s | %s | %s |" % (o["name"], o["type"], "" if o["value"] is None else "`" + o["value"] + "`", o["source"], note))

  md.append("")
  md.append("## Bases")
  md.append("")
  md.append("| label | base | rc | repetitions | distinct signatures | command |")
  md.append("|---|---|---|---|---|---|")

  for (label, base), b in sorted(base_sig.items()):
    md.append("| %s | %s | %d | %d | %d | `%s` |" % (label, base, b["rc"], b["runs"], b["variants"], b["ref"].get("repro", "")))

  unstable = [(k, b) for k, b in base_sig.items() if b["variants"] > 1]

  if len(unstable) > 0:
    md.append("")
    md.append("Bases whose repetitions differ (normalisation misses something, ignored-* findings on them are incomplete):")
    md.append("")

    for (label, base), b in unstable:
      ref = b["ref"]

      for other in b["all"]:
        if other["sig"] == ref["sig"]: continue

        md.append("* %s/%s:" % (label, base))
        md.append("")
        md.append("```")
        md += describe_diff(run_text(ref), run_text(other))
        md.append("```")

        break

  md.append("")
  md.append("## Runs per class")
  md.append("")
  md.append("| label | kind | class | runs |")
  md.append("|---|---|---|---|")

  for (label, kind, cls), n in sorted(counts.items()):
    md.append("| %s%s | %s | %s | %d |" % (label, " (sanitizer)" if label in san_labels else "", kind, cls, n))

  # Crashes and hangs, deduplicated. Every fault signature of a run is charged to the smallest
  # command line that shows it: the base, then a single option on the same base, then the pair.
  singles = {}

  for r in records:
    if r["kind"] == "single": singles[(r["label"], r["base"], r["opts"][0][0])] = r

  base_reports = collections.defaultdict(set)

  for r in records:
    if r["kind"] == "base": base_reports[(r["label"], r["base"])].update(r.get("reports", []))

  groups = collections.OrderedDict()

  for r in records:
    if (r["class"] in ("crash", "hang")) == False: continue

    known = set(base_reports[(r["label"], r["base"])])

    owner = "(base)"

    if r["kind"] != "base": owner = "+".join(o[0] for o in r["opts"])

    for rs in r.get("reports", []):
      who = owner

      if rs in known: who = "(base)"

      if (r["kind"] == "pair") and (who != "(base)"):
        for o in r["opts"]:
          sr = singles.get((r["label"], r["base"], o[0]))

          if sr is None: continue

          if rs in sr.get("reports", []): who = o[0]

      cls = "hang" if rs == "timeout" else "crash"

      g = groups.setdefault((cls, who), {"sigs": collections.Counter(), "runs": [], "bases": set()})

      g["sigs"][rs] += 1

      if (r in g["runs"]) == False: g["runs"].append(r)

      g["bases"].add(r["label"] + "/" + r["base"])

  # One entry per command line that owns a fault, with every signature it produced on every build,
  # and one reproduction per build: the release run shows the signal, the sanitizer run the place.
  for cls in ("crash", "hang"):
    md.append("")
    md.append("## %s" % ("Crashes" if cls == "crash" else "Hangs (timeout)"))
    md.append("")

    found = [(k, g) for k, g in groups.items() if k[0] == cls]

    if len(found) == 0:
      md.append("None.")

      continue

    for (c, owner), g in sorted(found, key=lambda x: (x[0][1].count("+"), x[0][1])):
      note = " (expected, runs until stopped)" if owner in EXCLUSIVE else ""

      title = owner if owner == "(base)" else "--" + owner.replace("+", " --")

      md.append("### %s%s" % (title, note))
      md.append("")
      md.append("%d runs, bases: %s" % (len(g["runs"]), ", ".join(sorted(g["bases"]))))
      md.append("")

      for rs, n in sorted(g["sigs"].items()):
        md.append("* %s (%d runs)" % (rs, n))

      md.append("")

      per_label = {}

      for r in sorted(g["runs"], key=lambda x: len(x["opts"])):
        per_label.setdefault(r["label"], r)

      for label, first in sorted(per_label.items()):
        md.append("%s, rc %s:" % (label, first.get("rc")))
        md.append("")
        md.append("```")
        md.append(first.get("repro", ""))
        md.append("```")

        # Only the fault blocks this owner is charged with, not the base's own reports.
        frames = []

        blocks = []

        for x in first.get("crash", []):
          if (x.startswith("#") == True) and (len(blocks) > 0):
            blocks[-1].append(x)
          else:
            blocks.append([x])

        for blk in blocks:
          if len(set(crash_reports(blk, 0, False)) & set(g["sigs"])) == 0: continue

          frames += blk[:7]

        if len(frames) > 0:
          md.append("")
          md.append("```")
          md += frames[:8]
          md.append("```")

        if "log" in first: md.append("log: %s" % first["log"])

        md.append("")

  slow = [r for r in records if (r.get("confirm") == True) and (r.get("timeout") == False)]

  md.append("")
  md.append("## Timed out once, finished when run again alone")
  md.append("")

  if len(slow) == 0: md.append("None.")

  for r in slow:
    md.append("* %s/%s: first run stopped at %s s, re-run took %s s, class %s: `%s`" % (r["label"], r["base"], r.get("first_elapsed"), r.get("elapsed"), r["class"], r.get("repro", "")))

  # Rejections, grouped by message.
  md.append("")
  md.append("## Rejected singles")
  md.append("")
  md.append("A single option rejected on a base. This is a declared conflict and is fine, it is listed so the table can be compared with the base list.")
  md.append("")

  rej = collections.defaultdict(list)

  for r in plain:
    if (r["kind"] == "single") and (r["class"] == "rejected"): rej[r["opts"][0][0]].append(r)

  for name in sorted(rej):
    rs = rej[name]

    md.append("* --%s on %s: %s" % (name, ", ".join(sorted(x["label"] + "/" + x["base"] for x in rs)), rs[0].get("msg", "")))

  # Applicability matrix: option x base.
  labels_bases = sorted(k for k in base_sig if (k[0] in san_labels) == False)

  md.append("")
  md.append("## Single option matrix")
  md.append("")
  md.append("C changes the run, I is accepted with no effect, R rejected, X crash, H hang, d already set by the base.")
  md.append("")
  md.append("| option | family | " + " | ".join("%s/%s" % lb for lb in labels_bases) + " |")
  md.append("|---|---|" + "---|" * len(labels_bases))

  letter = {"ok": "C", "ignored-single": "I", "rejected": "R", "crash": "X", "hang": "H", "duplicate": "d"}

  for o in options:
    row = []

    for lb in labels_bases:
      s = singles.get((lb[0], lb[1], o["name"]))

      row.append("" if s is None else letter.get(s["class"], "?"))

    md.append("| --%s | %s | %s |" % (o["name"], option_family(o["name"]), " | ".join(row)))

  # Ignored singles: suspects first, then the benign families.
  md.append("")
  md.append("## Ignored singles")
  md.append("")
  md.append("Accepted, same exit code, and the normalised output, outfile, potfile and created files are identical to the base run.")
  md.append("")

  # An option the base passes itself is tagged "harness" on that base, whatever its family.
  ign = {False: collections.defaultdict(list), True: collections.defaultdict(list)}

  for r in plain:
    if (r["kind"] != "single") or (r["class"] != "ignored-single"): continue

    name = r["opts"][0][0]

    fam = option_family(name)

    if name in base_sig[(r["label"], r["base"])]["harness"]: fam = "harness"

    r["family"] = fam

    ign[fam != ""][name].append(r)

  for want_family in (False, True):
    md.append("### %s" % ("Suspects (no benign family)" if want_family == False else "Plausibly benign by family"))
    md.append("")

    for name in sorted(ign[want_family]):
      rs = ign[want_family][name]

      fams = sorted({x["family"] for x in rs})

      tag = " [" + ",".join(fams) + "]" if want_family == True else ""

      md.append("* --%s%s on %s, e.g. `%s`" % (name, tag, ", ".join(sorted(x["label"] + "/" + x["base"] for x in rs)), rs[0].get("repro", "")))

    md.append("")

  # Shadowed in pair: grouped by the option that does the shadowing.
  md.append("## Ignored in pair")
  md.append("")
  md.append("Each option changes the run on its own, but the pair runs exactly like one of them alone. Grouped by the option that wins, with the options it silently swallows and the bases where that happens.")
  md.append("")

  # A pair lands under the suspects when neither option belongs to a benign family and neither is
  # one the base passes itself. The rest are listed after them, tagged.
  shadow = {False: collections.defaultdict(lambda: collections.defaultdict(list)), True: collections.defaultdict(lambda: collections.defaultdict(list))}

  info_count = collections.Counter()

  for r in plain:
    if r["class"] != "ignored-in-pair": continue

    if r["by"] in INFO_ONLY:
      info_count[r["by"]] += 1

      continue

    harness = base_sig[(r["label"], r["base"])]["harness"]

    tags = set()

    for name in [r["by"], r["shadowed"]]:
      for part in name.split("+"):
        if part in harness: tags.add("harness")

        if option_family(part) != "": tags.add(option_family(part))

    r["family"] = ",".join(sorted(tags))

    shadow[len(tags) > 0][r["by"]][r["shadowed"]].append(r)

  for want_family in (False, True):
    md.append("### %s" % ("Suspects (no benign family)" if want_family == False else "Plausibly benign by family"))
    md.append("")

    groups_by = shadow[want_family]

    for by in sorted(groups_by, key=lambda x: (-len(groups_by[x]), x)):
      victims = groups_by[by]

      md.append("* --%s swallows %d:" % (by.replace("+", " --"), len(victims)))

      for v in sorted(victims):
        rs = victims[v]

        fams = sorted({x["family"] for x in rs if x["family"] != ""})

        tag = " [" + ",".join(fams) + "]" if len(fams) > 0 else ""

        md.append("  * --%s%s on %s, e.g. `%s`" % (v, tag, ", ".join(sorted(x["label"] + "/" + x["base"] for x in rs)), rs[0].get("repro", "")))

    md.append("")

  for by, n in sorted(info_count.items()):
    md.append("--%s swallows %d pairs, as an option that prints and exits should." % (by, n))
    md.append("")

  with open(os.path.join(args.outdir, "REPORT.md"), "w") as f:
    f.write("\n".join(md) + "\n")

  # Written last, so the family tags the sections above assign are in it. The raw outputs and stack
  # lines stay in the JSONL files and the logs, each fault keeps its signature in "reports".
  slim = []

  for r in records:
    slim.append({k: v for k, v in r.items() if (k in ("out_n", "err_n", "files", "tree", "crash", "argv")) == False})

  with open(os.path.join(args.outdir, "runs.json"), "w") as f:
    json.dump(slim, f, separators=(",", ":"))

  if isinstance(args.emit_accepted, str):
    keys = sorted({r["key"] for r in records if (r["kind"] != "base") and ((r["class"] in ("rejected", "duplicate")) == False)})

    with open(args.emit_accepted, "w") as f:
      json.dump(keys, f)

  for (label, kind, cls), n in sorted(counts.items()):
    print("%-4s %-7s %-16s %d" % (label, kind, cls, n))

  return 0


VERDICT_FIELD = re.compile(r"(\w+)=(\S*)")

# Families for grouping the refusals in a comparison.
OPTION_FAMILIES = collections.OrderedDict([
  ("action",        ["backend-info", "benchmark", "benchmark-all", "benchmark-json", "benchmark-pure", "hash-info", "help", "identify", "keyspace", "total-candidates", "left", "lookup", "progress-only", "restore", "show", "speed-only", "stdout", "version", "module-cache-rebuild", "brain-feed", "brain-server"]),
  ("attack",        ["attack-mode", "custom-charset1", "custom-charset2", "custom-charset3", "custom-charset4", "custom-charset5", "custom-charset6", "custom-charset7", "custom-charset8", "hex-charset", "hex-wordlist", "encoding-from", "encoding-to", "wordlist-autohex-disable", "increment", "increment-inverse", "increment-min", "increment-max", "markov-classic", "markov-disable", "markov-hcstat2", "markov-inverse", "markov-threshold", "rules-file", "rules-concat", "generate-rules", "generate-rules-func-min", "generate-rules-func-max", "generate-rules-func-sel", "generate-rules-seed", "rule-left", "rule-right", "slow-candidates", "skip", "limit", "stdin-count", "stdin-timeout-abort", "loopback", "induction-dir"]),
  ("benchmark",     ["benchmark-min", "benchmark-max"]),
  ("output",        ["outfile", "outfile-format", "outfile-json", "outfile-autohex-disable", "outfile-check-dir", "outfile-check-timer", "potfile-disable", "potfile-path", "json", "machine-readable", "status", "status-json", "status-timer", "quiet", "pipeline-stats", "task-time-breakdown", "debug-file", "debug-mode", "color-cracked", "remove", "remove-timer", "keep-guessing", "encrypt-with-pubkey"]),
  ("device",        ["backend-devices", "backend-devices-virtmulti", "backend-devices-virthost", "backend-ignore-cuda", "backend-ignore-hip", "backend-ignore-opencl", "backend-ignore-metal", "opencl-device-types", "hwmon-disable", "hwmon-temp-abort", "cache-path", "metal-compiler-runtime"]),
  ("tuning",        ["optimized-kernel-enable", "multiply-accel-disable", "kernel-accel", "kernel-loops", "kernel-threads", "backend-vector-width", "spin-damp", "bitmap-min", "bitmap-max", "hook-threads", "scrypt-tmto", "cpu-affinity", "length-sort-disable", "self-test-disable", "bypass-delay", "bypass-threshold", "runtime"]),
  ("session",       ["session", "restore-disable", "restore-file-path", "restore-position", "logfile-disable", "force", "advice-disable", "deprecated-check-disable", "workload-profile"]),
  ("mode-specific", ["hash-type", "hash-recipe", "hash-copy", "hex-salt", "eapol-message-pair", "nonce-error-corrections", "keyboard-layout-mapping", "truecrypt-keyfiles", "veracrypt-keyfiles", "veracrypt-pim-start", "veracrypt-pim-stop", "bridge-parameter1", "bridge-parameter2", "bridge-parameter3", "bridge-parameter4", "dynamic-x", "username", "separator"]),
])


def refusal_family(name: str) -> str:
  for fam, names in OPTION_FAMILIES.items():
    if name in names: return fam

  if name.startswith("brain-"): return "brain"

  return "other"


def parse_verdict_line(line: str) -> dict:
  fields = {k: v for k, v in VERDICT_FIELD.findall(line)}

  return fields


def run_verdict(r: dict) -> dict:
  # What a run decided at startup. A run the validator refused carries its rule, a run that failed for
  # any other reason is "code", and the message is what the user saw.
  msg = "Usage: hashcat ..." if r.get("usage") == True else r.get("msg", "")

  # a run the harness could not make shows nothing about hashcat
  if ("harness_error" in r) or (("rc" in r) == False): return {"state": "error", "rule": "-", "opt": "-", "opt2": "-", "msg": r.get("harness_error", "")}

  if r.get("timeout") == True: return {"state": "hang", "rule": "-", "opt": "-", "opt2": "-", "msg": msg}

  if len(r.get("reports", [])) > 0: return {"state": "crash", "rule": "-", "opt": "-", "opt2": "-", "msg": msg}

  v = r.get("verdict") or {}

  if v.get("refuse") == "yes": return {"state": "refuse", "rule": v.get("rule", "-"), "opt": v.get("opt", "-"), "opt2": v.get("opt2", "-"), "msg": msg}

  if r.get("rc") in REFUSED_RC: return {"state": "refuse", "rule": "code", "opt": "-", "opt2": "-", "msg": msg}

  return {"state": "accept", "rule": "-", "opt": "-", "opt2": "-", "msg": msg}


def compare_class(a: dict, b: dict) -> str:
  if (a["state"] == "error") or (b["state"] == "error"): return "error"

  if (a["state"] == "hang") and (b["state"] == "hang"): return "hang-both"

  if b["state"] in ("crash", "hang"): return b["state"]

  if a["state"] in ("crash", "hang"): return a["state"] + "-fixed"

  if (a["state"] == "accept") and (b["state"] == "accept"): return "same-accept"
  if (a["state"] == "accept") and (b["state"] == "refuse"): return "new-refusal"
  if (a["state"] == "refuse") and (b["state"] == "accept"): return "lost-refusal"

  if (a["state"] == "refuse") and (b["state"] == "refuse"):
    if (a["rule"], a["opt"], a["opt2"], a["msg"]) == (b["rule"], b["opt"], b["opt2"], b["msg"]): return "same-refuse"

    return "refuse-changed"

  return "other"


def latest_records(paths: list) -> dict:
  out = collections.OrderedDict()

  for r in load_jsonl(paths):
    if (r.get("kind") in ("base", "single", "pair")) == False: continue

    if r.get("class_hint") == "duplicate": continue

    out[(r["base"], stable_key(r["key"]))] = r

  return out


def struct_agrees(r: dict) -> bool | None:
  # The frontend's static verdict, the first verdict line of a run, against the verdict hashcat
  # derives from the struct alone for a library caller. None where the run carries no struct line.
  st = r.get("struct")

  if st is None: return None

  verdicts = r.get("verdicts")

  first = verdicts[0] if isinstance(verdicts, list) and (len(verdicts) > 0) else (r.get("verdict") or {})

  agrees = (st.get("refuse") == first.get("refuse"))

  return agrees


def cmd_compare(args: argparse.Namespace) -> int:
  old = latest_records(args.old)
  new = latest_records(args.new)

  os.makedirs(args.outdir, exist_ok=True)

  counts = collections.Counter()

  groups = collections.defaultdict(lambda: collections.defaultdict(list))

  rows = []

  # Two checks on the new sweep alone: the verdict a library caller would get against the frontend's,
  # and the settings the table implies against the ones user_options_preprocess () made.
  checks = collections.Counter()

  check_examples = collections.defaultdict(list)

  for k, rb in new.items():
    agrees = struct_agrees(rb)

    if agrees == True:  checks["struct-same"]    += 1
    if agrees == False: checks["struct-differs"] += 1

    if agrees == False: check_examples["struct-differs"].append(rb.get("repro", ""))

    if any((d.get("holds") == "no") for d in rb.get("derive", []) or []):
      checks["derive-differs"] += 1

      check_examples["derive-differs"].append(rb.get("repro", ""))

    ra = old.get(k)

    if ra is None:
      counts["only-new"] += 1

      continue

    va = run_verdict(ra)
    vb = run_verdict(rb)

    cls = compare_class(va, vb)

    counts[cls] += 1

    rows.append({"key": rb["key"], "base": rb["base"], "kind": rb["kind"], "class": cls, "old": va, "new": vb, "repro": rb.get("repro", "")})

    if cls in ("same-accept", "same-refuse", "hang-both"): continue

    side = vb if cls != "lost-refusal" else va

    groups[cls][(side["rule"], side["opt"])].append(rows[-1])

  counts["only-old"] = len([k for k in old if (k in new) == False])

  # what fails the comparison as a gate
  failed = counts["crash"] + counts["hang"] + counts["lost-refusal"] + counts["error"] + counts["other"] + checks["struct-differs"]

  with open(os.path.join(args.outdir, "compare.jsonl"), "w") as f:
    for row in rows: f.write(json.dumps(row) + "\n")

  lines = ["%d runs compared, %s against %s" % (len(rows), " ".join(os.path.basename(p) for p in args.new), " ".join(os.path.basename(p) for p in args.old)), ""]

  for cls in ("same-accept", "same-refuse", "refuse-changed", "new-refusal", "lost-refusal", "crash", "hang", "hang-both", "crash-fixed", "hang-fixed", "error", "other", "only-new", "only-old"):
    lines.append("%-16s %8d" % (cls, counts[cls]))

  lines.append("")

  for chk in ("struct-same", "struct-differs", "derive-differs"):
    lines.append("%-16s %8d" % (chk, checks[chk]))

  lines.append("")
  lines.append("gate: %s" % ("FAIL" if failed > 0 else "ok"))

  for chk in ("struct-differs", "derive-differs"):
    if len(check_examples[chk]) == 0: continue

    lines.append("")
    lines.append("== %s: %d runs" % (chk, checks[chk]))

    for repro_line in check_examples[chk][:args.examples]:
      lines.append("      %s" % repro_line)

  for cls in ("crash", "hang", "error", "lost-refusal", "new-refusal", "refuse-changed", "crash-fixed", "hang-fixed", "other"):
    g = groups.get(cls)

    if g is None: continue

    lines.append("")
    lines.append("== %s: %d runs" % (cls, sum(len(v) for v in g.values())))

    for (rule, opt), rs in sorted(g.items(), key=lambda kv: -len(kv[1])):
      bases = collections.Counter(r["base"] for r in rs)

      lines.append("  rule %s, --%s [%s]: %d runs (%s)" % (rule, opt, refusal_family(opt), len(rs), ", ".join("%s %d" % kv for kv in sorted(bases.items()))))

      seen = set()

      for r in rs:
        pair = (r["old"]["msg"], r["new"]["msg"])

        if pair in seen: continue

        seen.add(pair)

        lines.append("      old: %s" % (r["old"]["msg"] or "(accepted)"))
        lines.append("      new: %s" % (r["new"]["msg"] or "(accepted)"))
        lines.append("      %s" % r["repro"])

        if len(seen) >= args.examples: break

  with open(os.path.join(args.outdir, "compare-summary.txt"), "w") as f:
    f.write("\n".join(lines) + "\n")

  print("\n".join(lines[:24]))

  rc = 1 if failed > 0 else 0

  return rc


def main() -> int:
  ap = argparse.ArgumentParser(description="Sweep hashcat command line options, alone and in pairs.")

  ap.add_argument("--hashcat-root", default=ROOT, help="build tree holding ./hashcat and the sources (default: this checkout)")

  sub = ap.add_subparsers(dest="cmd", required=True)

  p = sub.add_parser("list", help="print the enumerated options and their sample values")
  p.add_argument("--json", action="store_true")

  p = sub.add_parser("fixtures", help="write the input files the reproduction commands use")
  p.add_argument("dir")

  p = sub.add_parser("run", help="run a phase and append the results to a JSONL file")
  p.add_argument("--base", action="append", required=True, help="NAME=DEVICE_ARGS, e.g. bf=\"--backend-devices 1\"; known: " + " ".join(BASES))
  p.add_argument("--phase", choices=["base", "singles", "pairs", "exclusive", "confirm", "all"], default="all")
  p.add_argument("--out", required=True)
  p.add_argument("--workdir", required=True, help="per-worker trees, fixtures and logs go here")
  p.add_argument("--logdir", default=None)
  p.add_argument("--label", default="a", help="short tag for this host or build, part of the session names")
  p.add_argument("-j", "--jobs", type=int, default=8)
  p.add_argument("--timeout", type=int, default=30)
  p.add_argument("--base-repeats", type=int, default=3)
  p.add_argument("--exclude", action="append", default=[], help="option name to leave out")
  p.add_argument("--limit", type=int, default=0, help="run only the first N pending jobs")
  p.add_argument("--sanitizer", action="store_true", help="mark the runs as made with a sanitizer build: the report uses them for crashes and hangs only")
  p.add_argument("--keys-from", default=None, help="JSON list of run keys (base|opt+opt) to restrict the run to, see report --emit-accepted")
  p.add_argument("--device-mem-limit", type=int, default=0, help="HASHCAT_DEVICE_MEM_LIMIT for every run, in MiB")
  p.add_argument("--host-mem-limit", type=int, default=0, help="HASHCAT_HOST_MEM_LIMIT for every run, in MiB")
  p.add_argument("--verdict", action="store_true", help="run with HASHCAT_OPTION_DEBUG=1 and record the option table's verdicts")

  p = sub.add_parser("report", help="classify JSONL results and write runs.json and REPORT.md")
  p.add_argument("jsonl", nargs="+")
  p.add_argument("--outdir", required=True)
  p.add_argument("--emit-accepted", default=None, help="also write the keys of every run that was not rejected to this JSON file")

  p = sub.add_parser("compare", help="list the runs whose startup verdict differs between two sweeps")
  p.add_argument("--old", nargs="+", required=True)
  p.add_argument("--new", nargs="+", required=True)
  p.add_argument("--outdir", required=True)
  p.add_argument("--examples", type=int, default=3, help="example command lines per group")

  args = ap.parse_args()

  commands = {"list": cmd_list, "fixtures": cmd_fixtures, "run": cmd_run, "compare": cmd_compare, "report": cmd_report}

  rc = commands[args.cmd](args)

  return rc


if __name__ == "__main__":
  sys.exit(main())
