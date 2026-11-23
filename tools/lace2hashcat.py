#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

#
# Extracts Lace wallet vaults (SBV1 secret boxes) into hashcat hashes
# (mode 46002).
#
# Lace stores the recovery phrase sealed with the SBV1 secret box, hex-encoded,
# in the extension's storage (IndexedDB LevelDB). The binary envelope is:
# "SBV1"(4) + salt(32) + nonce(12) + ciphertext + tag(16).
#
# The database is read through plyvel on a copy of the directory, the way
# tools/atomic2hashcat.py does: LevelDB table blocks are Snappy compressed
# when that is smaller, so a byte scan of the files misses vaults.
#
# Usage:
#   lace2hashcat.py <leveldb-dir> [<leveldb-dir> ...]

import os
import re
import shutil
import sys
import tempfile

try:
  import plyvel
  HAVE_PLYVEL = True
except ImportError:
  HAVE_PLYVEL = False

MAGIC_HEX = b"53425631"  # "SBV1"

HEADER_LEN = 48
MIN_BODY   = 17  # 1 byte ct + 16 byte tag
MAX_BODY   = 2048 + 16

# a run of hex characters long enough to hold an envelope
HEX_RUN = re.compile(rb"[0-9a-fA-F]{%d,}" % ((HEADER_LEN + MIN_BODY) * 2))


def scan_value(value, out):
  for m in HEX_RUN.finditer(value):
    h = m.group(0)

    i = h.find(MAGIC_HEX)

    if i == -1:
      continue

    env_hex = h[i:]

    if len(env_hex) % 2 != 0:
      env_hex = env_hex[:-1]

    if len(env_hex) < (HEADER_LEN + MIN_BODY) * 2:
      continue

    try:
      env = bytes.fromhex(env_hex.decode())
    except ValueError:
      continue

    body = len(env) - HEADER_LEN

    if body < MIN_BODY or body > MAX_BODY:
      continue

    line = "$sbv1$" + env_hex.decode()

    if line not in out:
      out.append(line)


def process_dir(path, out):
  if not HAVE_PLYVEL:
    print("lace2hashcat: plyvel is not installed (pip install plyvel)", file=sys.stderr)
    sys.exit(1)

  with tempfile.TemporaryDirectory() as tmpdir:
    shutil.copytree(path, tmpdir, dirs_exist_ok=True)

    try:
      db = plyvel.DB(tmpdir, create_if_missing=False)

      for _, value in db:
        scan_value(bytes(value), out)

      db.close()
    except plyvel.Error as e:
      print("lace2hashcat: %s: not a LevelDB (%s)" % (path, e), file=sys.stderr)


def main():
  if len(sys.argv) < 2:
    print("usage: lace2hashcat.py <leveldb-dir> [<leveldb-dir> ...]", file=sys.stderr)
    sys.exit(1)

  out = []

  for path in sys.argv[1:]:
    if not os.path.isdir(path):
      print("lace2hashcat: %s: not a directory" % path, file=sys.stderr)
      continue

    process_dir(path, out)

  for h in out:
    print(h)

  if len(out) == 0:
    print("lace2hashcat: no SBV1 vaults found", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  main()
