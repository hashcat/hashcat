#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a Block.io backup wallet for hash-mode 37232.
#
# A Block.io backup, the "Backup Wallet" of the web interface or the user_key of a
# get_user_keys answer, holds a user_key object with a base64 encrypted_passphrase and an
# algorithm object. Every user_key found in the input is written out, one line each.
# Only the cipher, the iteration count, the salt, the iv and the first 16 bytes of the
# ciphertext are written, so the line carries nothing that identifies the wallet.

import argparse
import base64
import binascii
import json
import sys

# the ciphers a user_key can name, as the mode numbers them

CIPHERS = {"AES-256-ECB": 0, "AES-256-CBC": 1, "AES-256-GCM": 2}

IV_LEN = {0: 0, 1: 16, 2: 12}

# one AES block of the ciphertext is enough for the known plaintext the mode checks

CT_LEN = 16


def is_hex(s: str) -> bool:
  return len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)


def user_keys(obj) -> list:
  # the input is either a user_key itself or an object holding one, as data.user_key or
  # data.current_user_keys[].user_key

  if isinstance(obj, dict) == True:
    found = []

    if "encrypted_passphrase" in obj:
      found.append(obj)

    for value in obj.values(): found += user_keys(value)

    return found

  if isinstance(obj, list) == True:
    found = []

    for value in obj: found += user_keys(value)

    return found

  return []


def hash_line(user_key: dict) -> str:
  algo = user_key.get("algorithm") or {}

  name = algo.get("aes_cipher", "AES-256-ECB")

  if name not in CIPHERS: raise ValueError("the %s cipher is not supported" % name)

  cipher = CIPHERS[name]

  if algo.get("pbkdf2_hash_function", "SHA256") != "SHA256":
    raise ValueError("the %s hash function is not supported, only SHA256 is" % algo.get("pbkdf2_hash_function"))

  if algo.get("pbkdf2_phase1_key_length", 16) != 16 or algo.get("pbkdf2_phase2_key_length", 32) != 32:
    raise ValueError("the pbkdf2 key lengths are not supported, only 16 and 32 are")

  iterations = algo.get("pbkdf2_iterations", 2048)

  if not isinstance(iterations, int) or iterations < 2 or iterations % 2 != 0:
    raise ValueError("an iteration count of %s is not usable" % iterations)

  salt = algo.get("pbkdf2_salt") or ""

  if salt != "" and is_hex(salt) == False: raise ValueError("the salt is not hex")

  iv = algo.get("aes_iv") or ""

  if iv == "":
    if cipher != 0: raise ValueError("a %s backup without an iv is not supported" % name)
  else:
    if cipher == 0: raise ValueError("an AES-256-ECB backup takes no iv")

    if is_hex(iv) == False: raise ValueError("the iv is not hex")

    if len(iv) != IV_LEN[cipher] * 2:
      raise ValueError("the iv is %u bytes, %u are expected for %s" % (len(iv) // 2, IV_LEN[cipher], name))

  try:
    ct = base64.b64decode(user_key["encrypted_passphrase"], validate=True)
  except binascii.Error:
    raise ValueError("the encrypted_passphrase is not base64")

  if len(ct) < CT_LEN: raise ValueError("the ciphertext is %u bytes, at least %u are needed" % (len(ct), CT_LEN))

  line = "$blockio$1*%u*%u*%s*%s*%s" % (cipher, iterations, salt if salt else "-", iv if iv else "-", ct[:CT_LEN].hex())

  return line


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash line of a Block.io backup wallet for hash-mode 37232.")

  parser.add_argument("path", nargs="+", help="a file holding the backup, for example the backup JSON of the web interface or a get_user_keys answer")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      with open(path, "r") as fd:
        found = user_keys(json.load(fd))
    except json.JSONDecodeError as e:
      sys.stderr.write("%s: not JSON, %s\n" % (path, e.msg))

      rc = 1

      continue
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (path, e.strerror))

      rc = 1

      continue

    if len(found) == 0:
      sys.stderr.write("%s: no user_key found\n" % path)

      rc = 1

      continue

    for user_key in found:
      try:
        print(hash_line(user_key))
      except ValueError as e:
        sys.stderr.write("%s: %s\n" % (path, e))

        rc = 1

  return rc


if __name__ == "__main__":
  sys.exit(main())
