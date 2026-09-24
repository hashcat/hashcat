#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Run any test oracle (tools/test_modules/mNNNNN.py) inside hashcat through the Python bridge, modes
# 72000 and 73000. The oracle is then the hashing code hashcat cracks with, so a mode's reference
# implementation can be checked against hashcat's own parser and candidate handling, or stepped
# through, without a kernel.
#
#   python3 tools/test_bridge.py vectors 1000 /tmp/b.hash /tmp/b.words
#   ./hashcat -m 73000 --bridge-parameter1 tools/test_bridge.py /tmp/b.hash /tmp/b.words
#
# A bridge line is "sha256(H)*MODE:FAMILY:base64(H)", H being the oracle's own hash line. Mode
# 73000 splits a line at its first '*' and keeps at most 1024 bytes a side, and many oracle formats
# carry '*' of their own, so H travels base64 encoded in the salt half and the hash half is a fixed
# length digest of it. calc_hash hands H and the candidate to the oracle's module_verify_hash, which
# regenerates H from the line's own parameters, and returns the digest of that: it equals the hash
# half only when the candidate is the password. FAMILY is o or p, the IS_OPTIMIZED the vectors were
# generated under, because some oracles pick their charset from it.

import base64
import hashlib
import importlib.util
import os
import re
import struct
import subprocess
import sys


def _root():
  # The bridge compiles this file from source and may not set __file__, so fall back to the working
  # directory, which is the hashcat directory for a bridge run (it adds ./Python to sys.path).

  try:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  except NameError:
    return os.getcwd()


ROOT  = _root()
TESTS = os.path.join(ROOT, "tools", "test_modules")

for p in (TESTS, os.path.join(ROOT, "Python")):
  if p not in sys.path:
    sys.path.insert(0, p)

import hcshared  # noqa: E402
import hcsp      # noqa: E402

SALT_MAX = 1024

ST_PASS = "hashcat"
ST_HASH = "74ee1fae245edd6f27bf36efc3604942479fceefbadab5dc5c0b538c196eb0f1*0:o:ODc0M2I1MjA2M2NkODQwOTdhNjVkMTYzM2Y1Yzc0ZjU="

_ORACLES = {}


def _oracle(mode, family):
  # One module object per (mode, family): an oracle may fix its charset at import from IS_OPTIMIZED,
  # so the two families cannot share a copy. The variable is set on every call as well, for the
  # oracles that read it at call time.

  os.environ["IS_OPTIMIZED"] = "1" if family == "o" else "0"

  key = (mode, family)

  if key not in _ORACLES:
    path = os.path.join(TESTS, "m%05d.py" % mode)
    spec = importlib.util.spec_from_file_location("test_bridge_m%05d_%s" % (mode, family), path)
    mod  = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(mod)

    _ORACLES[key] = mod

  return _ORACLES[key]


def bridge_line(mode, family, oracle_hash):
  # oracle_hash is the oracle's hash line as bytes. Returns the bridge line, or None when it does
  # not fit the 1024 byte salt half.

  salt = b"%d:%s:%s" % (mode, family.encode("ascii"), base64.b64encode(oracle_hash))

  if len(salt) > SALT_MAX:
    return None

  return hashlib.sha256(oracle_hash).hexdigest().encode("ascii") + b"*" + salt


def calc_hash(password: bytes, salt: dict) -> str:
  mode, family, encoded = hcshared.get_salt_buf(salt).split(b":", 2)

  oracle_hash = base64.b64decode(encoded)

  got = _oracle(int(mode), family.decode("ascii")).module_verify_hash(oracle_hash + b":" + password)

  if got is None:
    return "invalid-password"

  return hashlib.sha256(got[0].encode("utf-8")).hexdigest()


def extract_esalts(esalts_buf):
  esalts = []

  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("1024s I 1024s I", esalts_buf):
    esalts.append({"hash_buf": hash_buf[0:hash_len], "salt_buf": salt_buf[0:salt_len]})

  return esalts


# Single process on purpose: it works under both 72000 and 73000, and on the platforms where 73000
# falls back to a single process anyway. An oracle is reference code, not a fast path.

def kernel_loop(ctx, passwords, salt_id, is_selftest):
  return hcsp.handle_queue(ctx, passwords, salt_id, is_selftest)


def init(ctx):
  hcsp.init(ctx, extract_esalts)


def term(ctx):
  hcsp.term(ctx)


# The oracle's test vectors, as test.py reads them: echo <word> | ./hashcat ${OPTS} -a 0 -m N '<h>'.

LINE = re.compile(rb"^echo (.*) \| \./hashcat \$\{OPTS\} -a 0 -m \d+ '(.*)'$")


def vectors(mode, pure, hash_path, word_path):
  family = "p" if pure else "o"

  env = dict(os.environ, IS_OPTIMIZED="0" if pure else "1")

  proc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "test_module_runner.py"), "single", str(mode)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  if proc.returncode != 0:
    sys.exit("! oracle failed for mode %d (rc=%d): %s" % (mode, proc.returncode, proc.stderr.decode(errors="replace").strip()))

  written = skipped = 0

  with open(hash_path, "wb") as hf, open(word_path, "wb") as wf:
    for raw in proc.stdout.splitlines():
      m = LINE.match(raw)

      if m is None:
        continue

      line = bridge_line(mode, family, m.group(2))

      if line is None:
        skipped += 1

        continue

      hf.write(line + b"\n")
      wf.write(m.group(1).rstrip(b" ") + b"\n")

      written += 1

  sys.stderr.write("%d vector(s) written, %d too long for the bridge's 1024 byte salt\n" % (written, skipped))


if __name__ == "__main__":
  args = sys.argv[1:]

  pure = "-P" in args

  args = [a for a in args if a != "-P"]

  if len(args) != 4 or args[0] != "vectors" or not args[1].isdigit():
    sys.exit("usage: %s vectors <mode> <hashfile> <wordfile> [-P]" % sys.argv[0])

  vectors(int(args[1]), pure, args[2], args[3])
