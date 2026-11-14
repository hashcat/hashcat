#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Extracts the crackable material from a Polkadot.js/SubWallet/Talisman keyring
# export JSON (or the vault record held by the browser extension) into the
# $subwallet$ hash line accepted by hashcat mode 79100.
#
# The exported JSON carries a base64 "encoded" blob:
#
#   salt(32) || N(u32le) || p(u32le) || r(u32le) || nonce(24) || tag(16) || ct
#
# and an "encoding" object that must name scrypt + xsalsa20-poly1305.

import base64
import json
import struct
import sys


def extract(path):
  with open(path) as f:
    data = json.load(f)

  encoding = data.get("encoding") or {}

  if "scrypt" not in encoding.get("type", []):
    raise ValueError("not a scrypt-encoded keyring (encoding.type: %s)" % encoding.get("type"))

  if "xsalsa20-poly1305" not in encoding.get("type", []):
    raise ValueError("not an xsalsa20-poly1305 keyring (encoding.type: %s)" % encoding.get("type"))

  blob = base64.b64decode(data["encoded"])

  salt = blob[0:32]
  n, p, r = struct.unpack("<III", blob[32:44])
  nonce = blob[44:68]
  tag = blob[68:84]
  ct = blob[84:]

  if len(salt) != 32 or len(nonce) != 24 or len(tag) != 16 or len(ct) == 0:
    raise ValueError("unexpected blob layout (len %d)" % len(blob))

  if len(ct) > 512:
    raise ValueError("ciphertext too long for mode 79100 (%d > 512 bytes)" % len(ct))

  return "$subwallet$%d,%d,%d$%s$%s$%s$%s" % (
    n, r, p,
    base64.b64encode(salt).decode(),
    base64.b64encode(nonce).decode(),
    base64.b64encode(tag).decode(),
    base64.b64encode(ct).decode())


def main():
  if len(sys.argv) < 2:
    sys.stderr.write("usage: %s <keyring-export.json> [...]\n" % sys.argv[0])
    sys.exit(1)

  rc = 0

  for path in sys.argv[1:]:
    try:
      print(extract(path))
    except Exception as e:
      sys.stderr.write("%s: %s\n" % (path, e))
      rc = 1

  sys.exit(rc)


if __name__ == "__main__":
  main()
