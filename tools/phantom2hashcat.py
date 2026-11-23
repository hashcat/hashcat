#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

#
# Extracts Phantom wallet vaults into hashcat hashes (modes 46000 and 46001).
#
# Phantom stores the vault in the Chrome extension's LevelDB (Local Extension
# Settings). Two on-disk generations exist:
#
#   v1: {"encryptedKey":{"digest":"sha256","encrypted":b58,"iterations":N,"kdf":"pbkdf2"|"scrypt","nonce":b58,"salt":b58},"version":1}
#   v0: {"expiry":...,"value":"<escaped v1-style JSON>"}
#
# The encrypted payload is a NaCl secretbox (XSalsa20-Poly1305) over the
# 32-byte secret, laid out as tag(16) || ct.
#
# The database is read through plyvel on a copy of the directory, the way
# tools/atomic2hashcat.py does: LevelDB table blocks are Snappy compressed
# when that is smaller, so a byte scan of the files misses vaults.
#
# Usage:
#   phantom2hashcat.py <leveldb-dir> [<leveldb-dir> ...]

import base64
import json
import os
import shutil
import sys
import tempfile

try:
  import plyvel
  HAVE_PLYVEL = True
except ImportError:
  HAVE_PLYVEL = False

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
  n = 0
  for c in s:
    n = n * 58 + B58_ALPHABET.index(c)

  b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""

  # leading '1's are zero bytes
  pad = 0
  for c in s:
    if c == "1":
      pad += 1
    else:
      break

  return b"\x00" * pad + b


def b64(b):
  return base64.b64encode(b).decode()


def emit(ek, out):
  """one vault entry -> hashcat line"""
  try:
    salt = b58decode(ek["salt"])
    nonce = b58decode(ek["nonce"])
    box = b58decode(ek["encrypted"])
    kdf = ek["kdf"].lower()
    iters = int(ek["iterations"])
  except (KeyError, ValueError):
    return

  if len(nonce) != 24:
    return

  if kdf == "scrypt":
    # Phantom hardcodes scrypt N=4096 r=8 p=1; the iterations field is unused
    h = "$phantom$s*4096*8*1*%s*%s*%s" % (b64(salt), b64(nonce), b64(box))
  elif kdf == "pbkdf2":
    h = "$phantom$p*%d*%s*%s*%s" % (iters, b64(salt), b64(nonce), b64(box))
  else:
    return

  if h not in out:
    out.append(h)


def process_value(value, out):
  """one LevelDB value: v1 JSON, v0 escaped JSON, possibly binary-prefixed"""
  idx = value.find(b"{")

  while idx != -1:
    try:
      v = json.loads(value[idx:].decode("utf-8", "replace"))
    except ValueError:
      idx = value.find(b"{", idx + 1)
      continue

    # v0 wrapper: {"expiry":...,"value":"<escaped v1 JSON>"}
    if isinstance(v, dict) and "encryptedKey" not in v and "value" in v:
      try:
        v = json.loads(str(v["value"]).replace("\\", ""))
      except (ValueError, TypeError):
        v = None

    if isinstance(v, dict) and "encryptedKey" in v:
      emit(v["encryptedKey"], out)

    idx = value.find(b"{", idx + 1)


def process_dir(path, out):
  if not HAVE_PLYVEL:
    print("phantom2hashcat: plyvel is not installed (pip install plyvel)", file=sys.stderr)
    sys.exit(1)

  with tempfile.TemporaryDirectory() as tmpdir:
    shutil.copytree(path, tmpdir, dirs_exist_ok=True)

    try:
      db = plyvel.DB(tmpdir, create_if_missing=False)

      for _, value in db:
        process_value(bytes(value), out)

      db.close()
    except plyvel.Error as e:
      print("phantom2hashcat: %s: not a LevelDB (%s)" % (path, e), file=sys.stderr)


def main():
  if len(sys.argv) < 2:
    print("usage: phantom2hashcat.py <leveldb-dir> [<leveldb-dir> ...]", file=sys.stderr)
    sys.exit(1)

  out = []

  for path in sys.argv[1:]:
    if not os.path.isdir(path):
      print("phantom2hashcat: %s: not a directory" % path, file=sys.stderr)
      continue

    process_dir(path, out)

  for h in out:
    print(h)

  if len(out) == 0:
    print("phantom2hashcat: no Phantom vaults found", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  main()
