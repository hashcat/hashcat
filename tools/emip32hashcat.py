#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

#
# Extracts Cardano EMIP-003 encrypted keys into hashcat hashes (mode 46003).
#
# EMIP-003 has no magic bytes: the blob is salt(32) + nonce(12) + tag(16) + ct,
# stored hex-encoded in the wallet's storage under keys like "encryptedKey"
# (old Nami) or "encryptedPrivateKey". Without a magic the extractor keys on
# those storage field names, and also accepts a raw blob file directly.
#
# Usage:
#   emip32hashcat.py <leveldb-dir|ldb-file|blob.hex> [...]
#
# The iteration count is not stored in the blob: 19162 is the EMIP-003 default
# (Eternl v2 uses 210012). The extractor emits 19162; if a wallet customized
# it, edit the field after the signature.

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

DEFAULT_ITERATIONS = 19162

HEADER_LEN = 60   # salt(32) + nonce(12) + tag(16)
MIN_BLOB   = HEADER_LEN + 1
MAX_BLOB   = HEADER_LEN + 2048

# hex run long enough to hold a blob, inside a JSON string
HEX_RUN = re.compile(rb'"[0-9a-fA-F]{%d,}"' % (MIN_BLOB * 2))

# storage fields known to hold an encrypted key blob
KEY_NAMES = [b"encryptedKey", b"encryptedPrivateKey", b"encryptedRootKey", b"encrypted_master_key", b"encryptedMasterKey"]


def try_emit(hexbytes, out):
  if len(hexbytes) % 2 != 0:
    return

  try:
    blob = bytes.fromhex(hexbytes.decode())
  except ValueError:
    return

  if len(blob) < MIN_BLOB or len(blob) > MAX_BLOB:
    return

  line = "$emip3$%d$%s" % (DEFAULT_ITERATIONS, blob.hex())

  if line not in out:
    out.append(line)


def scan_bytes(data, out):
  # only hex strings that sit under a known storage key, EMIP-003 has no magic
  for key in KEY_NAMES:
    pos = 0

    while True:
      idx = data.find(key, pos)

      if idx == -1:
        break

      pos = idx + 1

      m = HEX_RUN.search(data, idx + len(key))

      if m is None or m.start() > idx + len(key) + 8:
        continue

      try_emit(m.group(0)[1:-1], out)


def process_path(path, out):
  if os.path.isdir(path):
    # read through LevelDB on a copy, the way tools/atomic2hashcat.py does:
    # table blocks are Snappy compressed when that is smaller, so a byte scan
    # of the files misses blobs
    if not HAVE_PLYVEL:
      print("emip32hashcat: plyvel is not installed (pip install plyvel)", file=sys.stderr)
      sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
      shutil.copytree(path, tmpdir, dirs_exist_ok=True)

      try:
        db = plyvel.DB(tmpdir, create_if_missing=False)

        for key, value in db:
          key_b = bytes(key)
          value_b = bytes(value)

          # chrome.storage.local keeps the field name as the LevelDB key and the
          # blob as the value beside it
          if any(k in key_b for k in KEY_NAMES):
            stripped = value_b.strip().strip(b'"')

            if re.fullmatch(rb"[0-9a-fA-F]+", stripped):
              try_emit(stripped, out)

          scan_bytes(value_b, out)

        db.close()
      except plyvel.Error as e:
        print("emip32hashcat: %s: not a LevelDB (%s)" % (path, e), file=sys.stderr)

    return

  with open(path, "rb") as f:
    data = f.read()

  # a text file holding just the blob hex
  stripped = data.strip().strip(b'"')

  if re.fullmatch(rb"[0-9a-fA-F]+", stripped) and MIN_BLOB * 2 <= len(stripped) <= MAX_BLOB * 2:
    try_emit(stripped, out)

    if out:
      return

  scan_bytes(data, out)


def main():
  if len(sys.argv) < 2:
    print("usage: emip32hashcat.py <leveldb-dir|ldb-file|blob.hex> [...]", file=sys.stderr)
    sys.exit(1)

  out = []

  for path in sys.argv[1:]:
    if not os.path.exists(path):
      print("emip32hashcat: %s: no such file or directory" % path, file=sys.stderr)
      continue

    process_path(path, out)

  for h in out:
    print(h)

  if len(out) == 0:
    print("emip32hashcat: no EMIP-003 blobs found", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  main()
