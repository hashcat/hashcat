#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Extracts the crackable material from a Jaxx Liberty "mnemonic" record into
# the $jaxx$ hash line accepted by hashcat mode 79610.
#
# Jaxx Liberty stores the wallet in the browser/extension IndexedDB (leveldb).
# The record is JSON: {"et":"<b64>","iv":"<b64>","sb":"<b64>"}
#   sb = PBKDF2 salt, iv = AES-GCM nonce, et = ciphertext || 16B tag
#
# Input: the record as a JSON string in a file, or the raw leveldb value.

import base64
import json
import sys


def extract(raw):
  raw = raw.strip()

  # tolerate surrounding leveldb noise: cut from the first { to the last }
  start = raw.find("{")
  end = raw.rfind("}")

  if start == -1 or end == -1:
    raise ValueError("no JSON object found")

  data = json.loads(raw[start:end + 1])

  sb = base64.b64decode(data["sb"])
  iv = base64.b64decode(data["iv"])
  et = base64.b64decode(data["et"])

  if not (12 <= len(sb) <= 128):
    raise ValueError("sb length %d out of range" % len(sb))

  if not (12 <= len(iv) <= 16):
    raise ValueError("iv length %d out of range" % len(iv))

  if len(et) < 17:
    raise ValueError("et too short for ct || tag")

  return "$jaxx$%s$%s$%s" % (
    base64.b64encode(sb).decode(),
    base64.b64encode(iv).decode(),
    base64.b64encode(et).decode())


def main():
  if len(sys.argv) < 2:
    sys.stderr.write("usage: %s <record.json | leveldb-value.txt> [...]\n" % sys.argv[0])
    sys.exit(1)

  rc = 0

  for path in sys.argv[1:]:
    try:
      with open(path, errors="replace") as f:
        print(extract(f.read()))
    except Exception as e:
      sys.stderr.write("%s: %s\n" % (path, e))
      rc = 1

  sys.exit(rc)


if __name__ == "__main__":
  main()
