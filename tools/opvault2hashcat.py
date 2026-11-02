#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a 1Password OPVault for hash-mode 8200.
#
# An OPVault is a directory named *.opvault that holds its items in default/band_*.js and its key
# material in default/profile.js. The profile carries the PBKDF2-HMAC-SHA512 salt, the iteration
# count and the master key, an opdata01 blob whose last 32 bytes are an HMAC-SHA256 over the rest
# of it. The key for that HMAC is the second half of the derived key, so the blob verifies the
# password on its own, which is what hash-mode 8200 does.
#
# The OPVault design is documented at https://support.1password.com/opvault-design/

import argparse
import base64
import binascii
import json
import os
import sys

OPDATA_MAGIC = b"opdata01"

# the shortest opdata01 blob: the magic, the plaintext length, the IV, one cipher block and the MAC

OPDATA_LEN_MIN = 8 + 8 + 16 + 16 + 32

# the salt and the data field of hash-mode 8200, in bytes, from the token lengths in
# src/modules/module_08200.c

SALT_LEN = 16
DATA_LEN_MAX = 1024


def profile_file(path: str) -> str:
  if os.path.isfile(path) == True: return path

  for name in [os.path.join("default", "profile.js"), "profile.js"]:
    candidate = os.path.join(path, name)

    if os.path.isfile(candidate) == True: return candidate

  raise ValueError("no profile.js in %s, expected it in the default folder of the vault" % path)


# profile.js holds a JSON object in a var assignment, so take what stands between the braces

def read_profile(path: str) -> dict:
  with open(path, "r", encoding = "utf-8") as fd:
    buf = fd.read()

  start = buf.find("{")
  end   = buf.rfind("}")

  if (start < 0) or (end < start): raise ValueError("%s holds no JSON object" % path)

  return json.loads(buf[start:end + 1])


def hash_line(profile: dict) -> str:
  for name in ["salt", "masterKey", "iterations"]:
    if name not in profile: raise ValueError("the profile has no %s" % name)

  salt = base64.b64decode(profile["salt"], validate = True)

  if len(salt) != SALT_LEN: raise ValueError("the salt is %u bytes, hash-mode 8200 needs %u" % (len(salt), SALT_LEN))

  iterations = int(profile["iterations"])

  if iterations < 1: raise ValueError("the iteration count is %d" % iterations)

  blob = base64.b64decode(profile["masterKey"], validate = True)

  if blob[0:8] != OPDATA_MAGIC:    raise ValueError("the master key does not start with opdata01")
  if len(blob) < OPDATA_LEN_MIN:   raise ValueError("the master key is %u bytes, too short for an opdata01 blob" % len(blob))
  if (len(blob) - 32) % 16 != 0:   raise ValueError("the master key is %u bytes, which leaves no whole cipher blocks" % len(blob))

  # everything the HMAC covers, which is the blob without the HMAC itself

  data = blob[:-32]

  if len(data) > DATA_LEN_MAX: raise ValueError("the master key is %u bytes, hash-mode 8200 reads at most %u" % (len(blob), DATA_LEN_MAX + 32))

  return "%s:%s:%u:%s" % (blob[-32:].hex(), salt.hex(), iterations, data.hex())


def main() -> int:
  parser = argparse.ArgumentParser(description = "Write the hash line of a 1Password OPVault for hash-mode 8200")

  parser.add_argument("path", nargs = "+", help = "an .opvault folder, or the profile.js inside it")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      print(hash_line(read_profile(profile_file(path))))
    except (OSError, ValueError, KeyError, TypeError, binascii.Error) as e:
      print("%s: %s" % (path, e), file = sys.stderr)

      rc = 1

  return rc


if __name__ == "__main__":
  sys.exit(main())
