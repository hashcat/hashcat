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


def run_multi(opts, mode, pairs, args, width, file_only, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  hash_file = os.path.join(tmp, "m%05d_hashes.txt" % mode)

  if file_only:
    # test.sh:1225: every base64 hash decoded and concatenated into one file (22000/22001 keep their
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
    # test.sh gives the has_multi_hash modes one hash each, so there is no multi run and no line.
    # Everything else, binary hashfile included, runs one multi as test.sh does (its has_multi_hash
    # list omits the binary hashfile modes, so for those it runs a one-hash multi that ends Error).
    if has_multi_hash(r.mode):
      return

    run_multi(r.opts, r.mode, r.pairs, r.args, r.width, r.file_only, r.pass_only, r.tmp)


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
  # init()'s per mode line skip and split offset for the single-build dicts (test.sh:721-742).
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
  # Reproduce init()'s dict1/dict2 build (test.sh:744-789) as two byte-string lists, one line per
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
  # attack_1 single processes hashes whose 1-based index is in (min, max] (test.sh:1388-1405).

  smin, smax = 1, 8

  if mode in (14000, 14100, 14900, 15400):
    smin, smax = 0, 5
  elif mode == 20510:
    smin = 2

  return smin, smax


def combinator_multi_offset(mode):
  # attack_1 multi takes the last offset hashes as one batch (test.sh:1576-1586).

  if mode in (5800, 3000):
    return 6

  return 7


def pkzip_masterkey_dicts(dict1, dict2, line_nr):
  # test.sh:1439-1484, PKZIP master key. Rebuild the two dicts with line line_nr replaced by the
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
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

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
        # because init() left the length 1 line out (test.sh:1428-1434).
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
      # the same string -a 0 searches for (test.sh:1498-1505).

      matched = match_search(digest, word, r.pass_only) in out

      classify(rc, matched, c)

    if i == smax:
      break

  report(r.args, r.mode, "single", r.width, c, attack=1)


def run_combinator_multi(r, dict1_path, dict2_path):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  offset = combinator_multi_offset(r.mode)
  sel = r.pairs[-offset:]

  hash_file = os.path.join(r.tmp, "m%05d_multihash_combi.bin" % r.mode)

  if r.file_only:
    # test.sh concatenates the decoded files with no separator (test.sh:1597-1605). Reached only
    # if a non-slow binary hashfile mode ever gains a .py oracle; today none do.
    with open(hash_file, "wb") as fh:
      for _, digest in sel:
        fh.write(decode_hashfile(r.mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in sel) + b"\n")

  rc, out = run_hashcat(r.opts, r.mode, hash_file, b"", attack=1, extra=[dict1_path, dict2_path])

  # One hashcat run scored as one test (test.sh:1619-1659): every selected pair has to be in the
  # output, and each expected plain is the password because the halves rejoin to it.

  matched = all(match_search(digest, word, r.pass_only) in out for word, digest in sel)

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
  # test.sh mask_dots (test.sh:3989): a mask of <count> '?d' groups.

  return b"?d" * count


def mask_3(pos):
  # test.sh mask_3[] (test.sh:246): 'pos' '?d' groups, but never more than 15 of them; the length
  # beyond position 15 is spelled with literal '0's instead.

  if pos <= 15:
    return b"?d" * pos

  return b"?d" * 15 + b"0" * (pos - 15)


def mask_literalize(mask, text):
  # test.sh mask_literalize (test.sh:4004): rewrite a mask so each position spells the byte that
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
  # test.sh output_has_crack fallback (test.sh:411): hand the module's own verify the crack lines
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
  # test.sh output_has_crack (test.sh:394). The recovered line hash:password is looked for as it was
  # generated first. A mode that drops bits of the password can print a different password with the
  # same hash, so DES for one keeps 7 bits per byte, and a line that is not there verbatim is
  # re-checked by hash through the module's verify. A password only search has no hash to verify
  # against and stops at the plain comparison.

  if match_search(digest, word, pass_only) in out:
    return True

  if pass_only:
    return False

  prefix = digest.encode("ascii") + b":"
  crack_lines = [line for line in out.split(b"\n") if prefix in line]

  if not crack_lines:
    return False

  return run_verify(mode, digest, crack_lines, tmp)


def a3_single_max(mode):
  # test.sh attack_3 single (test.sh:1697): the number of hashes a single-hash run covers. Some
  # modes cap it lower because they carry a minimum password length.

  if mode in (14000, 14100, 14900, 15400):
    return 1

  if mode in (2500, 16800, 22000):
    return 7

  return 8


def a3_single_mask(mode, word, i):
  # test.sh attack_3 single mask (test.sh:1755): the first i bytes become a '?d' run rewritten to
  # spell them and the rest of the password trails as literals. 14000 and 14100 hand hashcat the
  # whole password as a literal mask instead, and 20510 drops the leading groups the mode does not
  # keep (test.sh:1777).

  if mode in (14000, 14100):
    return word

  mask = mask_literalize(mask_dots(i), word[:i]) + word[i:]

  if mode == 20510:
    cut_pos = 13 if i > 6 else i + 7
    mask = mask[cut_pos - 1:]

  return mask


def attack_3_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  max_i     = a3_single_max(r.mode)
  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)

  i = 1

  for word, digest in r.pairs:
    # test.sh:1721: a slow mode stops after the sixth hash.
    if i > 6 and is_timeout(r.mode):
      break

    # test.sh:1748: a mask cannot produce a password shorter than itself, so that hash is skipped
    # and does not count.
    if len(word) < i:
      i += 1

      continue

    # test.sh:1771: PKZIP master key needs at least two '?d' groups to keep after the cut.
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
  # test.sh attack_3 multi (test.sh:1882): the --increment window. A slow mode narrows it, and the
  # modes with a minimum password length move it up.

  increment_min = 1
  increment_max = 5 if is_timeout(mode) else 8

  if mode in (2500, 16800, 22000):
    increment_min = 8
    increment_max = 9

  return increment_min, increment_max


def a3_custom_charsets(mode, sel_passwords):
  # test.sh attack_3 multi (test.sh:2009): 2500, 16800 and 22000 pin the mask to ?d?d?d?d?d?1?2?3?4
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
  # test.sh:1873: the modes with one hash each have no multi-hash run.
  if has_multi_hash(r.mode):
    return

  increment_min, increment_max = a3_multi_increment(r.mode)

  words   = [w for w, _ in r.pairs]
  digests = [d for _, d in r.pairs]

  head_hashes = sum(1 for w in words if len(w) <= increment_max)
  tail_hashes = sum(1 for w in words if increment_min <= len(w) <= increment_max)

  # test.sh:1934: one --increment run cannot spell a password that carries a multi byte character,
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
  # only on the plain --increment path (test.sh:2005, 2242).

  custom = a3_custom_charsets(r.mode, words[:len(sel)])

  if r.mode in (2500, 16800, 22000):
    mask_arg = b"?d?d?d?d?d?1?2?3?4"

  increment_opts = []

  if need_hcmask == 0:
    increment_opts = ["--increment", "--increment-min", str(increment_min),
                      "--increment-max", str(increment_max)] + custom

  rc, out = run_hashcat(r.opts, r.mode, hash_file, None, attack=3,
                        extra=increment_opts + [mask_arg])

  # test.sh:2260: one hashcat run scored as one test; every selected pair must be in the output,
  # matched by hash where the printed password differs from the generated one.

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

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
# dict1_multi/dict2_multi (test.sh:818-880). MULTI_CACHE holds each batch so a length is asked of the
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
  # test.sh init () multi split (test.sh:791-816). min_len shifts the split toward the tail, and a
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
  elif mode == 33500:
    fixed_len = 5
  elif mode == 33501:
    min_len   = 5
    fixed_len = 9
  elif mode == 33502:
    min_len   = 5
    fixed_len = 13

  return min_len, fixed_len


def multi_pairs(mode, i, optimized):
  # test.sh init () (test.sh:834-845): the eight passwords for length slot i, from the same oracle
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
  # test.sh init () (test.sh:858-876): split each length-i password into dict1_multi (head) and
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
  # test.sh attack_6 single (test.sh:2333-2359). mask_offset drives a first-line custom split that
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
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  min_i, max_i = a6_single_params(r.mode)

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict1_a6  = os.path.join(r.tmp, "m%05d_a6_dict1" % r.mode)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1

    # test.sh:2393: a slow mode stops after the sixth hash.
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

      # test.sh:2433: the index is the mask length, capped one byte below the password so a mode
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
      # carries the whole password even for 20510 whose run word was cut (test.sh:2501-2514).

      line_nr = i - 1 if i > 1 else 1

      search_word = sed_line(dict1_lines, line_nr) + sed_line(dict2_lines, line_nr)

      matched = output_has_crack(r.mode, out, search_word, digest,
                                 r.pass_only, r.tmp) if rc == 0 else False

      classify(rc, matched, c)

    if i == max_i:
      break

  report(r.args, r.mode, "single", r.width, c, attack=6)


def a6_multi_params(mode):
  # test.sh attack_6 multi (test.sh:2587-2615).

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
  elif mode in (33501, 33502):
    min_i = 8

  if is_timeout(mode):
    max_i = 5

    if mode == 3200:
      max_i = 3

  return min_i, max_i


def attack_6_multi(r):
  if has_multi_hash(r.mode):
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

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
    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    write_hashes(hash_file, pairs, r.mode, r.file_only)
    write_dict(dict1_mp, d1)

    # The eight passwords of a length share one mask over the tail dict1 does not hold, spelled by
    # any of them since the length seeds their layout (test.sh:2653-2656).

    multi_model = pairs[0][0] if pairs else b""
    multi_head  = d1[0] if d1 else b""
    multi_tail  = multi_model[len(multi_head):]

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
  # test.sh attack_7 single (test.sh:2743-2770). mask_offset drives the min == 0 custom split.

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
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  min_i, max_i, mask_offset = a7_single_params(r.mode)
  optimized = not r.args.pure

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file  = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict2_base = os.path.join(r.tmp, "m%05d_a7_dict2" % r.mode)
  dict2_cust = os.path.join(r.tmp, "m%05d_a7_dict2_custom" % r.mode)

  write_dict(dict2_base, dict2_lines)

  # The min == 0 modes build a one line custom pair from the first password, split at mask_offset
  # (test.sh:2774-2800). The custom mask test.sh forms there is overwritten below, so only the dicts
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
        # test.sh:2901-2927. The length-slot mask only sizes the split, then a one line custom pair
        # is rebuilt around the 6 byte prefix the mode drops.
        pass_full = sed_line(dict1_lines, line_nr) + sed_line(dict2_lines, line_nr)

        if len(pass_full) <= 6:
          continue

        mpairs     = multi_pairs(20510, i, optimized) if "multi" in r.targets else []
        md1, _     = build_multi_dicts(20510, i, mpairs)
        multi_head = md1[0] if md1 else b""
        slot_mask  = mask_literalize(mask_dots(len(multi_head)), multi_head)
        mask_len   = len(slot_mask) // 2

        cut     = pass_full[6:]
        cust_d1 = [pass_full[:6 + mask_len]]
        cust_d2 = [cut[mask_len:]]

        write_dict(dict2_cust, cust_d2)

        active = True

      if active:
        d1_lines = cust_d1
        d2_lines = cust_d2
        d2_path  = dict2_cust

      # -a 7 is mask plus dict, dict2 holds the tail, so the mask spells the head that dict1 holds.
      # It is built from what dict1 actually holds rather than from a fixed table, because a split
      # moved to a character boundary changes dict1's length (test.sh:2946-2947).

      dict1_line = sed_line(d1_lines, line_nr)
      mask       = mask_literalize(mask_dots(len(dict1_line)), dict1_line)

      rc, out = run_hashcat(r.opts, r.mode, target, None, attack=7,
                            extra=hybrid_extra([mask, d2_path]))

      search_word = sed_line(d1_lines, line_nr) + sed_line(d2_lines, line_nr)

      matched = output_has_crack(r.mode, out, search_word, digest,
                                 r.pass_only, r.tmp) if rc == 0 else False

      classify(rc, matched, c)

    if i == max_i:
      break

  report(r.args, r.mode, "single", r.width, c, attack=7)


def a7_multi_max(mode):
  # test.sh attack_7 multi (test.sh:3047-3082). 33500 sets a min the loop never reads, so only max
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

  if is_timeout(mode):
    max_i = 7

    if mode == 3200:
      max_i = 4

  return max_i


def attack_7_multi(r):
  if has_multi_hash(r.mode):
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0}

  max_i     = a7_multi_max(r.mode)
  optimized = not r.args.pure

  hash_file  = os.path.join(r.tmp, "m%05d_a7_hashes_multi.txt" % r.mode)
  dict2_mp   = os.path.join(r.tmp, "m%05d_a7_dict2_multi" % r.mode)
  dict2_long = os.path.join(r.tmp, "m%05d_a7_dict2_multi_longer" % r.mode)

  i = 2

  while i < max_i:
    pairs  = multi_pairs(r.mode, i, optimized)
    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    # The mask spells the head dict2 does not hold. 40001 and 40002 read it from a table instead,
    # but neither has a python oracle so neither is reached here (test.sh:3098-3104).

    multi_head = d1[0] if d1 else b""
    mask       = mask_literalize(mask_dots(len(multi_head)), multi_head)

    write_hashes(hash_file, pairs, r.mode, r.file_only)

    if r.file_only:
      # test.sh:3125-3145: a file based mode keeps the mask short by moving the rest of each
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


# One function per attack mode, each printing test.sh's summary lines for that attack. An attack
# that is not here yet is reported once on stderr and left to test.sh.

ATTACKS = {
  0: attack_0,
  1: attack_1,
  3: attack_3,
  4: attack_4,
  6: attack_6,
  7: attack_7,
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
