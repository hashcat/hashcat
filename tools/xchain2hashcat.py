#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write a hashcat hash line for an xchain-crypto keystore, which is what thorchain and thorswap
# wallets save. The file looks like an Ethereum keystore and carries the same cipher and the same
# key derivation, but its mac is BLAKE2b rather than keccak256, so it goes to mode 15800 and not to
# mode 15600.
#
# Reference: xchainjs-lib, packages/xchain-crypto/src/crypto.ts

import argparse
import json
import sys

CIPHERTEXT_MAX = 256
SALT_MAX       = 32


def hex_problem(name, value):
  if isinstance(value, str) == False:
    return "%s is not a string" % name

  if (len(value) % 2) != 0:
    return "%s has an odd number of hex characters" % name

  try:
    bytes.fromhex(value)
  except ValueError:
    return "%s is not hex" % name

  return None


def int_field(name, value):
  # Wallets write these as numbers and sometimes as numeric strings, so int() is right. A field that
  # is neither has to be refused rather than raising out of the script.

  try:
    return (int(value), None)
  except (TypeError, ValueError):
    return (None, "%s is not a number" % name)


def keystore_to_line(j):
  if "crypto" not in j:
    return (None, "no crypto member, so this is not a keystore")

  crypto = j["crypto"]

  for name in ["ciphertext", "mac", "cipher", "kdf", "kdfparams"]:
    if name not in crypto:
      return (None, "the crypto member has no %s" % name)

  # An Ethereum keystore reaches this script easily, because the two differ only in the mac. Its
  # version is 3 where an xchain keystore says 1, and a line written for the wrong one of the two
  # would load and then never crack, so the version is checked rather than assumed.

  if "version" not in j:
    return (None, "no version member, so this is not a keystore")

  version, problem = int_field("the version", j["version"])

  if problem is not None:
    return (None, problem)

  if version != 1:
    return (None, "the keystore is version %i, so it is not an xchain keystore. "
                  "A version 3 keystore goes to hash-mode 15600 or 15700" % version)

  ciphertext = crypto["ciphertext"]
  mac        = crypto["mac"]
  kdfparams  = crypto["kdfparams"]

  if isinstance(kdfparams, dict) == False:
    return (None, "kdfparams is not an object")

  salt = kdfparams.get("salt", "")

  for name, value in [("the ciphertext", ciphertext), ("the mac", mac), ("the salt", salt)]:
    problem = hex_problem(name, value)

    if problem is not None:
      return (None, problem)

  if len(mac) != 64:
    return (None, "the mac is %i hex characters rather than 64" % len(mac))

  if len(ciphertext) == 0:
    return (None, "the ciphertext is empty")

  if crypto["cipher"] != "aes-128-ctr":
    return (None, "the cipher is %s, and this mode hashes the mac key of an aes-128-ctr keystore" % crypto["cipher"])

  if crypto["kdf"] not in ["pbkdf2", "pbkdf2-sha256"]:
    return (None, "the kdf is %s, and xchain keystores derive with pbkdf2" % crypto["kdf"])

  prf = kdfparams.get("prf", "hmac-sha256")

  if prf != "hmac-sha256":
    return (None, "the pbkdf2 prf is %s, and this mode cracks hmac-sha256" % prf)

  dklen, problem = int_field("dklen", kdfparams.get("dklen", 32))

  if problem is not None:
    return (None, problem)

  if dklen != 32:
    return (None, "dklen is %i rather than 32" % dklen)

  if "c" not in kdfparams:
    return (None, "the pbkdf2 parameters have no c")

  if len(salt) > (SALT_MAX * 2):
    return (None, "the salt is %i bytes, and hashcat takes at most %i" % (len(salt) // 2, SALT_MAX))

  if len(ciphertext) > (CIPHERTEXT_MAX * 2):
    return (None, "the payload is %i bytes, and hashcat takes at most %i" % (len(ciphertext) // 2, CIPHERTEXT_MAX))

  c, problem = int_field("the pbkdf2 c", kdfparams["c"])

  if problem is not None:
    return (None, problem)

  line = "$xchain$*%i*%s*%s*%s" % (c, salt, ciphertext, mac)

  return (line, None)


def file_to_line(path):
  try:
    with open(path, "rb") as fh:
      j = json.loads(fh.read().decode("utf-8", "ignore"))
  except (OSError, ValueError) as e:
    return (None, "cannot be read as json: %s" % e)

  if isinstance(j, dict) == False:
    return (None, "the file is not a json object")

  return keystore_to_line(j)


def main():
  parser = argparse.ArgumentParser(description="Write hashcat hash lines for xchain-crypto keystore "
                                               "files, as thorchain and thorswap wallets save them, "
                                               "for hash-mode 15800.")

  parser.add_argument("files", nargs="+", help="keystore .json files")

  args = parser.parse_args()

  failed = 0

  for path in args.files:
    # A keystore is a file somebody downloaded, so anything one file does has to stay with that
    # file. Without the catch, a crafted file ends the run and the remaining paths on the command
    # line are never looked at: json.loads raises RecursionError, not ValueError, on deeply nested
    # input, and that is only the instance we know about.

    try:
      line, problem = file_to_line(path)
    except Exception as e:
      line    = None
      problem = "cannot be read as a keystore: %s" % type(e).__name__

    if problem is not None:
      print("%s: %s" % (path, problem), file=sys.stderr)

      failed += 1

      continue

    print(line)

  if failed > 0:
    return 1

  return 0


if __name__ == "__main__":
  sys.exit(main())
