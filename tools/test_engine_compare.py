#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Run both test engines over one mode and require them to agree.

A conversion replaces mXXXXX.pm with mXXXXX.py, and the suite passing afterwards only says the mode
still cracks. It does not say the python oracle behaves like the perl one it replaced. This runs
both over the entry points tools/test.sh and tools/test_edge.sh drive, and compares what comes back.

Two comparisons, because one of them is not always possible:

  Cross verification, always. Each engine verifies what the other generated. A hash one engine
  produced and the other re-derives from its own fields is the same algorithm in both, whatever
  salt was drawn. This is the check that means something for the fourteen modes whose .pm shells
  out to python3, because that embedded script draws from its own generator and no seed reaches it.

  Byte comparison, where both engines are seedable. HCTEST_SEED puts both on one generator, so the
  same salts and the same words come out and the hashes can be compared line for line. The tool
  finds out by running each engine twice: an engine that gives two different answers to one seed is
  not seedable, and says so instead of failing.

Both are run for the optimized and the unoptimized kernel, and the invalid input list has to be
rejected by both.

A converted mode has no .pm left in the tree, so the perl side is taken out of git: --ref names
where to find it, origin/master by default.

Usage:
  tools/test_engine_compare.py 17010
  tools/test_engine_compare.py --all
  tools/test_engine_compare.py --ref HEAD~5 --seed 42 --verbose 9000 14500
"""

import argparse
import difflib
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT  = os.path.dirname(TOOLS)

# the words the passthrough and potthrough entry points are fed. Short, long, at the optimized
# kernel's 31 byte edge, all digits, and one that is not ASCII, because a mode that takes one has
# to take it in both engines.

WORDS = [
  b"hashcat",
  b"a",
  b"0123456789",
  b"hashcat-hashcat-hashcat-hashca",
  b"hashcat-hashcat-hashcat-hashcat",
  b"p@ssw0rd!",
  "hashc\u00e4t".encode("utf-8"),
]

# lines a module has to reject rather than accept or crash on. The engines have to agree here too: a
# python oracle that takes what the perl one refused is one that will pass a broken hash through the
# suite.

INVALID = [
  b"",
  b"not-a-hash",
  b"$",
  b"*",
  b":",
  b"::::",
  b"$HEX[]",
  b"$HEX[zz]",
  b"0123456789abcdef",
  b"a" * 512,
  b"\xff\xfe\x00\x01",
]


def run(cmd, cwd, env, stdin=None):
  return subprocess.run(cmd, cwd=cwd, env=env, input=stdin,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def module_deps(source):
  # a .pm that pulls another file in, so the perl side gets what it needs

  return re.findall(r"require\s+[\"\']([\w./-]+)[\"\']", source)


def stage_perl(mode, ref, workdir):
  # The perl engine loads its module out of test_modules/ beside itself, so both go into a
  # directory of their own. The .pm comes from the tree where it is still there and out of git
  # where the conversion already removed it.

  name = "m%05d.pm" % mode

  tools = os.path.join(workdir, "tools")
  mods  = os.path.join(tools, "test_modules")

  os.makedirs(mods, exist_ok=True)

  shutil.copy2(os.path.join(TOOLS, "test_module_runner.pl"), tools)

  # The runner reads src/modules and OpenCL relative to itself, to decide whether a mode takes a
  # password that is not ASCII. Staged on its own it would find neither and quietly answer no for
  # every mode, so the staging directory mirrors the tree around it.

  for mirror in ("src", "OpenCL", "deps", "docs"):
    target = os.path.join(ROOT, mirror)
    link   = os.path.join(workdir, mirror)

    if os.path.exists(target) and not os.path.exists(link):
      os.symlink(target, link)

  in_tree = os.path.join(TOOLS, "test_modules", name)

  if os.path.exists(in_tree):
    shutil.copy2(in_tree, mods)

    source = open(in_tree, "r", errors="replace").read()

    origin = "the tree"
  else:
    got = subprocess.run(["git", "show", "%s:tools/test_modules/%s" % (ref, name)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if got.returncode != 0:
      return None, "no %s in the tree and none at %s" % (name, ref)

    source = got.stdout.decode("utf-8", "replace")

    with open(os.path.join(mods, name), "wb") as handle:
      handle.write(got.stdout)

    origin = ref

  for dep in module_deps(source):
    dep_in_tree = os.path.join(TOOLS, "test_modules", dep)

    if os.path.exists(dep_in_tree):
      shutil.copy2(dep_in_tree, mods)

      continue

    got = subprocess.run(["git", "show", "%s:tools/test_modules/%s" % (ref, dep)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if got.returncode == 0:
      with open(os.path.join(mods, dep), "wb") as handle:
        handle.write(got.stdout)

  return os.path.join(tools, "test_module_runner.pl"), origin


class Engine:
  def __init__(self, name, cmd, cwd):
    self.name = name
    self.cmd  = cmd
    self.cwd  = cwd

  def __call__(self, env, *args, stdin=None):
    return run(self.cmd + list(args), self.cwd, env, stdin)


def env_for(seed, optimized):
  env = dict(os.environ)

  env["HCTEST_SEED"]  = str(seed)
  env["IS_OPTIMIZED"] = "1" if optimized else "0"

  return env


def seedable(engine, env, mode, words):
  # two runs of one seed, and whatever comes back has to be the same twice

  first  = engine(env, "potthrough", str(mode), stdin=words)
  second = engine(env, "potthrough", str(mode), stdin=words)

  return first.stdout == second.stdout, first.stdout, first.returncode


def cross_verify(source, checker, env, mode, workdir, pairs, tag):
  # what one engine generated goes through the other's module_verify_hash. A line comes back only
  # if the checker re-derived the hash out of its own fields and found it in the hash list, so a
  # line that does not come back is a hash the checker cannot account for.

  if not pairs.strip():
    return True, "%-34s nothing generated, skipped" % tag

  hashes = b"\n".join(line.rsplit(b":", 1)[0] for line in pairs.splitlines() if b":" in line) + b"\n"

  hashes_file = os.path.join(workdir, "cross_hashes.txt")
  cracks_file = os.path.join(workdir, "cross_cracks.txt")
  out_file    = os.path.join(workdir, "cross_out.txt")

  with open(hashes_file, "wb") as handle:
    handle.write(hashes)

  with open(cracks_file, "wb") as handle:
    handle.write(pairs)

  if os.path.exists(out_file):
    os.unlink(out_file)

  checker(env, "verify", str(mode), hashes_file, cracks_file, out_file)

  got = open(out_file, "rb").read() if os.path.exists(out_file) else b""

  wanted = len([line for line in pairs.splitlines() if line.strip()])
  have   = len([line for line in got.splitlines() if line.strip()])

  if have == wanted:
    return True, "%-34s %d of %d accounted for" % (tag, have, wanted)

  missing = [line for line in pairs.splitlines() if line not in got.splitlines()]

  detail = "\n".join("      " + line.decode("utf-8", "replace")[:160] for line in missing[:3])

  return False, "%-34s %d of %d accounted for\n%s" % (tag, have, wanted, detail)


def compare(label, left, right, verbose):
  if left == right:
    return True, "%-34s same" % label

  diff = list(difflib.unified_diff(left.decode("utf-8", "replace").splitlines(),
                                   right.decode("utf-8", "replace").splitlines(),
                                   "perl", "python", lineterm="", n=1))

  shown = diff if verbose else [line[:160] for line in diff[:10]]

  detail = "\n".join("      " + line for line in shown)

  return False, "%-34s DIFFERS\n%s" % (label, detail)


def reject_invalid(engine, env, mode, workdir, tag):
  # every line in INVALID has to be refused. What the engine writes out is what it accepted.

  hashes_file = os.path.join(workdir, "invalid_hashes.txt")
  cracks_file = os.path.join(workdir, "invalid_cracks.txt")
  out_file    = os.path.join(workdir, "invalid_out.txt")

  with open(hashes_file, "wb") as handle:
    handle.write(b"\n".join(line.rsplit(b":", 1)[0] for line in INVALID) + b"\n")

  with open(cracks_file, "wb") as handle:
    handle.write(b"\n".join(INVALID) + b"\n")

  if os.path.exists(out_file):
    os.unlink(out_file)

  engine(env, "verify", str(mode), hashes_file, cracks_file, out_file)

  got = open(out_file, "rb").read() if os.path.exists(out_file) else b""

  return got


def check_mode(mode, ref, seed, verbose):
  results = []

  if not os.path.exists(os.path.join(TOOLS, "test_modules", "m%05d.py" % mode)):
    return [(False, "m%05d has no python oracle" % mode)]

  workdir = tempfile.mkdtemp(prefix="engine_compare_")

  try:
    perl_runner, origin = stage_perl(mode, ref, workdir)

    if perl_runner is None:
      # nothing to compare against is not the same as a disagreement: a mode converted before this
      # branch has no .pm left at the reference either

      return [(True, "m%05d: %s, nothing to compare" % (mode, origin))]

    results.append((True, "%-34s %s" % ("perl oracle from", origin)))

    perl = Engine("perl", ["perl", perl_runner], os.path.join(workdir, "tools"))
    py   = Engine("python", ["python3", os.path.join(TOOLS, "test_module_runner.py")], ROOT)

    words = b"\n".join(WORDS) + b"\n"

    for optimized in (False, True):
      env = env_for(seed, optimized)

      tag = "-O" if optimized else "  "

      perl_stable, perl_pairs, perl_rc = seedable(perl, env, mode, words)
      py_stable,   py_pairs,   py_rc   = seedable(py, env, mode, words)

      # A mode with no kernel of the family the run asked for is not applicable, and the two
      # engines say so differently on purpose: the python one exits 2, which tools/test.sh turns
      # into a Skip, while the perl one copies the other family's constraints and reports as if
      # the kernel were there. That is a documented difference rather than a defect, so the rest
      # of the checks for this kernel family are not run.

      if py_rc == 2:
        results.append((True, "%-34s not applicable, the python engine skips the mode and the "
                        "perl one substitutes the other kernel" % ("kernel family %s" % tag)))

        continue

      # one engine generating where the other does not is a difference in its own right, and the
      # checks below would quietly skip it

      if bool(perl_pairs.strip()) != bool(py_pairs.strip()):
        has, has_not = ("perl", "python") if perl_pairs.strip() else ("python", "perl")

        results.append((False, "%-34s %s generated %d lines, %s generated none"
                        % ("passthrough %s" % tag, has,
                           len([line for line in (perl_pairs if has == "perl" else py_pairs).splitlines() if line.strip()]),
                           has_not)))

      # 1. self verification first. An engine that cannot account for its own output says nothing
      # about the other one, and several .pm files on master are in exactly that state, so the
      # cross check below is only reported as a failure where the checker passed this.

      perl_self_ok, perl_self = cross_verify(perl, perl, env, mode, workdir, perl_pairs,
                                             "perl verifies perl %s" % tag)

      py_self_ok, py_self = cross_verify(py, py, env, mode, workdir, py_pairs,
                                         "python verifies python %s" % tag)

      results.append(("ok" if perl_self_ok else "perl", perl_self))
      results.append(("ok" if py_self_ok else "fail", py_self))

      # 2. cross verification, which needs no seed at all

      ok, text = cross_verify(perl, py, env, mode, workdir, perl_pairs,
                              "python verifies perl %s" % tag)

      results.append(("ok" if (ok or not py_self_ok) else "fail",
                      text if ok else text + "\n      "
                      "(the python oracle does not verify its own output either)"))

      ok, text = cross_verify(py, perl, env, mode, workdir, py_pairs,
                              "perl verifies python %s" % tag)

      results.append(("ok" if ok else ("perl" if not perl_self_ok else "fail"),
                      text if ok else text + "\n      "
                      "(the perl oracle does not verify its own output either, so this is its own defect)"))

      # 3. byte comparison, where the seed reaches both

      if perl_stable and py_stable:
        results.append(compare("potthrough %s" % tag, perl_pairs, py_pairs, verbose))

        p = perl(env, "single", str(mode)).stdout
        y = py(env, "single", str(mode)).stdout

        results.append(compare("single %s" % tag, p, y, verbose))

        for attack in (0, 1, 3):
          p = perl(env, "edge", str(mode), str(attack), "1" if optimized else "0").stdout
          y = py(env, "edge", str(mode), str(attack), "1" if optimized else "0").stdout

          results.append(compare("edge a%d %s" % (attack, tag), p, y, verbose))
      else:
        which = " and ".join(name for name, stable in
                             (("the perl oracle", perl_stable), ("the python oracle", py_stable))
                             if not stable)

        results.append((True, "%-34s skipped, %s draws from a generator HCTEST_SEED does not reach"
                        % ("byte comparison %s" % tag, which)))

      # 4. invalid input, which both have to refuse

      left  = reject_invalid(perl, env, mode, workdir, tag)
      right = reject_invalid(py, env, mode, workdir, tag)

      ok, text = compare("invalid input %s" % tag, left, right, verbose)

      if ok and left.strip():
        ok, text = False, "%-34s both engines accepted:\n      %s" % (
          "invalid input %s" % tag, left.decode("utf-8", "replace").strip()[:200])

      results.append((ok, text))

    return results
  finally:
    shutil.rmtree(workdir, ignore_errors=True)


def main():
  parser = argparse.ArgumentParser(description="run both test engines over a mode and compare")

  parser.add_argument("modes", nargs="*", type=int, help="hash modes to compare")
  parser.add_argument("--all", action="store_true", help="every mode with a python oracle")
  parser.add_argument("--ref", default="origin/master", help="where to read a .pm the tree no longer has")
  parser.add_argument("--seed", type=int, default=1, help="HCTEST_SEED handed to both engines")
  parser.add_argument("--verbose", action="store_true", help="print the whole difference")

  args = parser.parse_args()

  modes = args.modes

  if args.all:
    modes = sorted(int(os.path.basename(p)[1:6])
                   for p in glob.glob(os.path.join(TOOLS, "test_modules", "m?????.py")))

  if not modes:
    parser.print_help()

    return 2

  failed      = []
  perl_defect = []

  for mode in modes:
    print("m%05d" % mode)

    results = check_mode(mode, args.ref, args.seed, args.verbose)

    states = [(state if isinstance(state, str) else ("ok" if state else "fail"), text)
              for state, text in results]

    marks = {"ok": "  ", "fail": "!>", "perl": "..."}

    for state, text in states:
      print("  %s %s" % (marks[state], text))

    if any(state == "fail" for state, _ in states):
      failed.append(mode)
    elif any(state == "perl" for state, _ in states):
      perl_defect.append(mode)

  print()

  if perl_defect:
    print("the perl oracle cannot verify its own output for %d of %d modes, which is a defect of "
          "the .pm rather than of the conversion: %s"
          % (len(perl_defect), len(modes), " ".join("m%05d" % m for m in perl_defect)))

  if failed:
    print("engines disagree on %d of %d modes: %s"
          % (len(failed), len(modes), " ".join("m%05d" % m for m in failed)))

    return 1

  print("engines agree on all %d modes" % len(modes))

  return 0


if __name__ == "__main__":
  sys.exit(main())
