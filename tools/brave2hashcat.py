#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Extracts the crackable material from a Brave Browser profile's Preferences
# file into the $brave$ hash line accepted by hashcat mode 79630.
#
# The Brave Wallet vault lives in two Preferences keys:
#   brave.wallet.encrypted_mnemonic = {"ciphertext": b64, "nonce": b64}
#   brave.wallet.encryptor_salt     = b64 (32 bytes)
#
# Iterations are not stored: 310000 since 2022-08 (brave-core PR #14523),
# 100000 before. Emit both; the wrong one simply does not crack.

import base64
import json
import sys


def extract(path):
  with open(path, errors="replace") as f:
    prefs = json.load(f)

  wallet = prefs.get("brave", {}).get("wallet", {})

  em = wallet.get("encrypted_mnemonic")
  salt_b64 = wallet.get("encryptor_salt")

  if not em or not salt_b64:
    raise ValueError("brave.wallet.encrypted_mnemonic / encryptor_salt not found")

  ct = base64.b64decode(em["ciphertext"])
  nonce = base64.b64decode(em["nonce"])
  salt = base64.b64decode(salt_b64)

  if len(nonce) != 12:
    raise ValueError("unexpected nonce length %d" % len(nonce))

  if len(salt) != 32:
    raise ValueError("unexpected salt length %d" % len(salt))

  if len(ct) < 16:
    raise ValueError("ciphertext too short for ct || tag")

  lines = []

  for iters in (310000, 100000):
    lines.append("$brave$*%d*%s*%s*%s" % (iters, salt.hex(), nonce.hex(), ct.hex()))

  return lines


def main():
  if len(sys.argv) < 2:
    sys.stderr.write("usage: %s <Preferences> [...]\n" % sys.argv[0])
    sys.exit(1)

  rc = 0

  for path in sys.argv[1:]:
    try:
      for line in extract(path):
        print(line)
    except Exception as e:
      sys.stderr.write("%s: %s\n" % (path, e))
      rc = 1

  sys.exit(rc)


if __name__ == "__main__":
  main()
