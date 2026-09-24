#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# A python manager, the counterpart to tools/test.sh for the modes that have a python oracle. It
# asks tools/test_module_runner.py for test vectors, runs ./hashcat on them and reports the same
# OK/Error/Skip summary line test.sh prints, so the two can be compared line for line. It is being
# grown one attack mode at a time; ATTACKS lists the ones it runs, and test.sh still owns the rest.

import argparse
import base64
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

TDIR   = os.path.dirname(os.path.abspath(__file__))
ROOT   = os.path.dirname(TDIR)
RUNNER = os.path.join(TDIR, "test_module_runner.py")
BIN    = os.path.join(ROOT, "hashcat")

SINGLE_MAX = 32     # test.sh caps a single-target run at 32 hashes
RUNTIME    = 400    # hashcat --runtime, as test.sh sets it

# A binary-hashfile mode (OPTS_TYPE_BINARY_HASHFILE) is handed a file, not a hash string, so the
# oracle prints the file base64 encoded and the manager decodes it back to a file (test.sh:894,
# 1062). For those, and for the two encoding exceptions, the recovered line does not carry the
# hash we started from, so the match is on ":password" alone (test.sh PASS_ONLY, line 6876).

NOCHECK_ENCODING = {16800, 22000}

# The LUKS modes whose hashes are container paths, not the generator's own output. whole_word_vectors
# leaves their -a 4 list alone (test.sh:487); 10300 takes its hash from another field and is excluded
# there too.

LUKS_MODES = {29511, 29512, 29513, 29521, 29522, 29523, 29531, 29532, 29533, 29541, 29542, 29543,
              34100}

# The modes test.sh's has_multi_hash reports true for: one hash each, so no multi-hash run at all
# (test.sh:524).

MULTI_ONE_HASH = {14000, 14100, 14600, 14900, 15400}

# test.sh's attack order for -a all (test.sh:7362-7431). A slow mode only runs the attacks that
# cost one candidate per word (the whole word attacks), so it gets 0, 4, 8 and 9 and nothing else,
# even when another attack is asked for by number.

ATTACK_ORDER = [0, 4, 8, 9, 1, 3, 6, 7, 12]
WHOLE_WORD   = (0, 4, 8, 9)

# SLOW_ALGOS is every module with ATTACK_EXEC_OUTSIDE_KERNEL plus these, whose generated passwords
# the mask attacks cannot express (test.sh:212, 230). 400 is run as a fast hash on purpose, to cover
# the AMP kernel (test.sh:7253).

FAKE_SLOW = {28501, 28502, 28503, 28504, 28505, 28506, 30901, 30902, 30903, 30904, 30905, 30906,
             34700}

# The oracle writes one shell line per vector: echo <word> | ./hashcat ${OPTS} -a 0 -m <n> '<h>'.
# The word is padded to 31 with trailing spaces by the "%-31s" the oracle uses; the hash is single
# quoted and holds no single quote of its own.

LINE = re.compile(rb"^echo (.*) \| \./hashcat \$\{OPTS\} -a 0 -m \d+ '(.*)'$")

# -a 4 asks the pcfg device engine for OpenCL/mNNNNN_a4-optimized.cl by the mode's kern_type, not by
# the mode number, so the file test is on the kern_type read out of the module (test.sh:218).

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


def is_slow(mode):
  if mode == 400:
    return False

  return mode in FAKE_SLOW or b"ATTACK_EXEC_OUTSIDE_KERNEL" in module_source(mode)


def host_engine(mode):
  # test.sh HOST_ENGINE_ALGOS is the plain ATTACK_EXEC_OUTSIDE_KERNEL set (test.sh:225), taken before
  # the fake-slow additions, so it is read straight off the module and does not carry FAKE_SLOW.

  return b"ATTACK_EXEC_OUTSIDE_KERNEL" in module_source(mode)


def is_timeout(mode):
  # test.sh TIMEOUT_ALGOS is SLOW_ALGOS as written (test.sh:7183), which keeps 400 that is_slow drops
  # for attack selection. It caps a single-hash whole-word run at 12 vectors instead of 32.

  return mode in FAKE_SLOW or host_engine(mode)


def a4_optimized(mode):
  # Whether the mode ships an optimized pcfg kernel, named by its kern_type (test.sh:218).

  m = KERN_TYPE_RE.search(module_source(mode))

  if m is None:
    return False

  return os.path.isfile(os.path.join(ROOT, "OpenCL", "m%05d_a4-optimized.cl" % int(m.group(1))))


def a4_optimized_skip(mode, optimized):
  # test.sh:1011: an optimized -a 4 pass on a mode whose kernel runs inside the device and that ships
  # no optimized pcfg kernel would be refused by hashcat, so the pass is skipped and, unlike a normal
  # skip, prints no summary line. The pure pass covers the attack for such a mode.

  return optimized and not host_engine(mode) and not a4_optimized(mode)


def has_multi_hash(mode):
  return mode in MULTI_ONE_HASH


def oracle_spare(mode, optimized, length):
  # test.sh whole_word_vectors:506: one vector of a fixed length from the same oracle, to stand in for
  # a word -a 4 cannot express. Returns (word, digest) or None.

  env = dict(os.environ)
  env["IS_OPTIMIZED"] = "1" if optimized else "0"

  proc = subprocess.run([sys.executable, RUNNER, "single", str(mode), str(length)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  if proc.returncode != 0:
    return None

  for line in proc.stdout.splitlines():
    m = LINE.match(line)

    if m is not None:
      return (m.group(1).rstrip(b" "), m.group(2).decode("ascii"))

  return None


def a4_vectors(mode, pairs, optimized):
  # test.sh whole_word_vectors (test.sh:469): a grammar builds its candidate out of terminals of at
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

  if is_slow(mode):
    wanted = [a for a in wanted if a in WHOLE_WORD]

  return wanted


def decode_hashfile(mode, digest):
  # test.sh:894/1062: the base64 decodes to the file hashcat reads. 22000/22001 are handed their
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

    pairs.append((m.group(1).rstrip(b" "), m.group(2).decode("ascii")))

  return pairs


def classify(rc, matched, c):
  # Mirror test.sh exactly. A hashcat run that exits 0 but whose output does not carry the pair is
  # rewritten to code 10 (test.sh:987, 1157), then status() buckets by the code (test.sh:737-839):
  # 1 exhausted, 4 --runtime, 10 not matched, the specific runtime-skip codes to skipped, and any
  # other code, 247 included, to not found through the default case. The set is spelled out rather
  # than as a range because test.sh omits 247.

  c["cnt"] += 1

  ret = (0 if matched else 10) if rc == 0 else rc

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
  else:
    c["nf"] += 1


def verdict(c):
  if c["rs"]:
    return "Skip"

  if c["nf"] or c["nm"] or c["cnt"] == 0:
    return "Error"

  if c["to"]:
    return "Warning"

  return "OK"


def run_hashcat(opts, mode, target, stdin_bytes, attack=0, extra=()):
  cmd = [BIN] + opts + ["-a", str(attack), "-m", str(mode), target] + list(extra)

  # Run from the repo root, the way test.sh does, so hashcat finds OpenCL/ and caches kernels/
  # there rather than in whatever directory the manager was invoked from.

  proc = subprocess.run(cmd, input=stdin_bytes, cwd=ROOT,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  return proc.returncode, proc.stdout + proc.stderr


def context(args, mode, target_name, width, attack=0):
  # test.sh pads the multi label with a second space so the Device-Type column lines up under the
  # longer "single" (test.sh:1019 vs 1187). Kept so the part after the leading label matches it
  # byte for byte.

  mode_field = "single, " if target_name == "single" else "multi,  "

  return ("[ test.py ] [ Type %d, Attack %d, Mode %sDevice-Type %s, Kernel-Type %s, Vector-Width %d ]"
          % (mode, attack, mode_field, DEVICE_LABEL.get(args.device, args.device),
             "Pure" if args.pure else "Optimized", width))


def report(args, mode, target_name, width, c, attack=0):
  print("%s > %s : %d/%d not found, %d/%d not matched, %d/%d timeout, %d/%d skipped"
        % (context(args, mode, target_name, width, attack), verdict(c),
           c["nf"], c["cnt"], c["nm"], c["cnt"], c["to"], c["cnt"], c["rs"], c["cnt"]))


def report_skip(args, mode, target_name, width, reason, attack=0):
  print("%s > Skip : %s" % (context(args, mode, target_name, width, attack), reason))


def match_search(digest, word, pass_only):
  # test.sh:950-954: normally the recovered line is hash:password; for a file based or
  # encoding-exception mode only the password half is ours to check.

  if pass_only:
    return b":" + word

  return digest.encode("ascii") + b":" + word


def run_single(opts, mode, pairs, args, width, file_only, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  temp_file = os.path.join(tmp, "m%05d_filebased.bin" % mode)

  for word, digest in pairs[:SINGLE_MAX]:
    if file_only:
      with open(temp_file, "wb") as fh:
        fh.write(decode_hashfile(mode, digest))

      target = temp_file
    else:
      target = digest

    rc, out = run_hashcat(opts, mode, target, word + b"\n")

    matched = match_search(digest, word, pass_only) in out

    classify(rc, matched, c)

  report(args, mode, "single", width, c)


def run_multi(opts, mode, pairs, args, width, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  hash_file = os.path.join(tmp, "m%05d_hashes.txt" % mode)

  with open(hash_file, "wb") as fh:
    fh.write(b"\n".join(d.encode("ascii") for _, d in pairs) + b"\n")

  stdin_bytes = b"\n".join(w for w, _ in pairs) + b"\n"

  rc, out = run_hashcat(opts, mode, hash_file, stdin_bytes)

  # test.sh scores the whole batch as one test: one hashcat run, every pair has to be in the
  # output, and status is called once (test.sh:1116-1173). So the count here is 1, not one per hash
  # the way single is, and classify does the "cracked but a pair is missing" rewrite.

  matched = all(match_search(digest, word, pass_only) in out for word, digest in pairs)

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
    # A binary hashfile holds one hash per file, so there is no multi-hash run to make. This is
    # test.sh's has_multi_hash reason ("we only have 1 hash for each of them"), which its hardcoded
    # list misses for these modes.
    if r.file_only:
      report_skip(r.args, r.mode, "multi", r.width, "binary hashfile mode has one hash per file")
    else:
      run_multi(r.opts, r.mode, r.pairs, r.args, r.width, r.pass_only, r.tmp)


def build_ruleset(ruleset_dir, words):
  # test.sh whole_word_ruleset (test.sh:444): the smallest pcfg that emits exactly this word list. X
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
  # test.sh whole_word_source (test.sh:426): the argv each whole-word attack takes after the hash. -a
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
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  optimized = not r.args.pure

  if attack == 4:
    subst   = a4_vectors(r.mode, r.pairs, optimized)
    vectors = subst if subst is not None else r.pairs
  else:
    vectors = r.pairs

  # test.sh:1035: a single-hash run stops at 32 vectors, or 12 for a slow mode.

  max_n = 12 if is_timeout(r.mode) else 32

  temp_file   = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  words_file  = os.path.join(r.tmp, "m%05d_a%d_words" % (r.mode, attack))
  ruleset_dir = os.path.join(r.tmp, "m%05d_a%d_ruleset" % (r.mode, attack))

  for word, digest in vectors[:max_n]:
    candidate = word

    if r.mode == 20510:
      # PKZIP master key: hashcat is fed the key without its 6 byte prefix, the recovered line still
      # carries the whole password (test.sh:1078).
      candidate = word[6:]

    if attack == 4 and len(candidate) == 0:
      # A ruleset cannot write an empty candidate, so it is skipped rather than run (test.sh:1085).
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

    matched = match_search(digest, word, r.pass_only) in out

    classify(rc, matched, c)

  report(r.args, r.mode, "single", r.width, c, attack)


def whole_word_multi(r, attack):
  # test.sh:1196: the modes with one hash each have no multi-hash run, -a 9 gives one candidate per
  # salt so its multi case is left to test_edge.sh, and a binary hashfile has no line to drop so -a 4
  # keeps its single coverage only.

  if has_multi_hash(r.mode):
    return

  if attack == 9:
    return

  if attack == 4 and r.file_only:
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  optimized = not r.args.pure

  if attack == 4:
    # test.sh:1249: -a 4 runs on the substituted list, or on the -a 0 list with the empty word
    # dropped where no spare could be drawn.
    subst  = a4_vectors(r.mode, r.pairs, optimized)
    mpairs = subst if subst is not None else [(w, d) for w, d in r.pairs if w != b""]
  else:
    mpairs = r.pairs

  hash_file   = os.path.join(r.tmp, "m%05d_hashes.txt" % r.mode)
  words_file  = os.path.join(r.tmp, "m%05d_a%d_multi_words" % (r.mode, attack))
  ruleset_dir = os.path.join(r.tmp, "m%05d_a%d_multi_ruleset" % (r.mode, attack))

  if r.file_only:
    # test.sh:1225: every base64 hash decoded and concatenated into one file, the raw line kept for
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

  matched = all(match_search(digest, word, r.pass_only) in out for word, digest in mpairs)

  classify(rc, matched, c)

  report(r.args, r.mode, "multi", r.width, c, attack)


def whole_word(r, attack):
  if attack == 4 and a4_optimized_skip(r.mode, not r.args.pure):
    # No summary line at all, the same as test.sh which logs the skip to logfull only (test.sh:1011).
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


# One function per attack mode, each printing test.sh's summary lines for that attack. An attack
# that is not here yet is reported once on stderr and left to test.sh.

ATTACKS = {
  0: attack_0,
  4: attack_4,
  8: attack_8,
  9: attack_9,
}


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
  opts = ["--quiet", "--potfile-disable", "--logfile-disable"]

  if not args.pure:
    opts.append("-O")

  opts += ["--runtime", str(RUNTIME), "-D", args.device]

  if args.force:
    opts.append("--force")

  return opts


def main():
  ap = argparse.ArgumentParser(description="python manager for the hashcat -a 0 test path")

  ap.add_argument("-m", dest="mode", default="all", help="N | all | min-max")
  ap.add_argument("-a", dest="attack", default="0", help="0 | 1 | 3 | 4 | 6 | 7 | 8 | 9 | 12 | all")
  ap.add_argument("-t", dest="target", default="all", choices=["single", "multi", "all"])
  ap.add_argument("-D", dest="device", default="2", help="OpenCL device type")
  # -O is accepted and does nothing, as in test.sh where optimized is already the default; -P is
  # what switches to the pure kernel, and if both are given -P wins.
  ap.add_argument("-O", dest="optimized", action="store_true", help="optimized kernels (default)")
  ap.add_argument("-P", dest="pure", action="store_true", help="pure kernels")
  ap.add_argument("-f", dest="force", action="store_true", help="pass --force to hashcat")
  ap.add_argument("-V", dest="vector", default="default", help="1 | 4 | default (both)")

  args = ap.parse_args()

  if args.attack != "all" and (not args.attack.isdigit() or int(args.attack) not in ATTACK_ORDER):
    die("! invalid attack mode: %s" % args.attack)

  if args.attack != "all" and int(args.attack) not in ATTACKS:
    die("! -a %s is not implemented in test.py yet, tools/test.sh still covers it" % args.attack)

  if not os.path.isfile(BIN):
    die("! no hashcat binary at %s, build it first" % BIN)

  # Confirm the oracle engine is here before the run: a missing script would exit 2, which is the
  # code the engine uses for "no kernel for this family", so without this a missing engine would
  # be misread as every mode being not applicable.

  if not os.path.isfile(RUNNER):
    die("! no oracle engine at %s" % RUNNER)

  modes    = discover_modes()
  selected = select_modes(args.mode, modes)
  targets  = targets_for(args.target)
  widths   = widths_for(args.vector)

  skips   = []
  missing = set()

  with tempfile.TemporaryDirectory(prefix="test_py_") as tmp:
    for mode in selected:
      pairs = oracle_vectors(mode, not args.pure)

      if pairs is None:
        reason = "no %s kernel for this mode" % ("Pure" if args.pure else "Optimized")

        skips.append((mode, reason))

        print("[ test.py ] [ Type %d ] > Skip : %s" % (mode, reason))

        continue

      file_only = is_file_only(mode)
      pass_only = file_only or mode in NOCHECK_ENCODING

      # PKZIP master key only has a single hash test; a forced multi run is skipped outright
      # (test.sh:7258-7263).

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
    sys.stderr.write("! not implemented in test.py yet, tools/test.sh still covers: -a %s\n"
                     % ", ".join(str(a) for a in sorted(missing)))

  if skips:
    print()
    print("[ test.py ] > %d test(s) did not run in full:" % len(skips))

    for mode, reason in skips:
      print("[ test.py ] [ Type %d ] > Skip : %s" % (mode, reason))


main()
