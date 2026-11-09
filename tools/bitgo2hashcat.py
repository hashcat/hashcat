#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a BitGo wallet key for hash-mode 37231.
#
# BitGo encrypts the xprv of a key with sjcl, and the blob, the JSON object
# {"iv":...,"iter":...,"ks":...,"ct":...}, is usually stored as a JSON string, as in the
# encryptedPrv field of a keychain or a keycard. Every blob found in the input is written out, one
# line each.
# Only the iteration count, the key size, the salt, the iv and the first 16 bytes of the ciphertext
# are written, so the line carries nothing of the key itself.

import argparse
import base64
import binascii
import json
import sys

# the sjcl fields that have to be there, and the ones whose values this supports

REQUIRED = ("iv", "salt", "ct", "iter", "ks")

KEY_SIZES = (128, 256)

SALT_LEN = 8
IV_LEN   = 16

# one AES block of the ciphertext is enough for the known plaintext the mode checks

CT_LEN = 16


def b64_field(obj: dict, name: str, want_len: int) -> bytes:
  try:
    raw = base64.b64decode(obj[name], validate=True)
  except binascii.Error:
    raise ValueError("%s is not base64" % name)

  if want_len > 0:
    if len(raw) != want_len: raise ValueError("%s is %u bytes, expected %u" % (name, len(raw), want_len))

  return raw


def blobs(obj) -> list:
  # the input is either the blob itself, the blob as a string, or an object holding one of those

  if isinstance(obj, str) == True:
    try:
      return blobs(json.loads(obj))
    except json.JSONDecodeError:
      return []

  if isinstance(obj, dict) == True:
    found = []

    for name in REQUIRED:
      if name not in obj: break
    else:
      found.append(obj)

    for value in obj.values(): found += blobs(value)

    return found

  if isinstance(obj, list) == True:
    found = []

    for value in obj: found += blobs(value)

    return found

  return []


def hash_line(blob: dict) -> str:
  mode = blob.get("mode", "ccm")

  if mode != "ccm": raise ValueError("the %s mode is not supported, only ccm is" % mode)

  cipher = blob.get("cipher", "aes")

  if cipher != "aes": raise ValueError("the %s cipher is not supported, only aes is" % cipher)

  if blob.get("adata", "") != "": raise ValueError("a blob with associated data is not supported")

  key_size = blob["ks"]

  if key_size not in KEY_SIZES: raise ValueError("a key size of %s is not supported" % key_size)

  iterations = blob["iter"]

  if iterations < 1: raise ValueError("an iteration count of %s is not usable" % iterations)

  salt = b64_field(blob, "salt", SALT_LEN)
  iv   = b64_field(blob, "iv",   IV_LEN)
  ct   = b64_field(blob, "ct",   0)

  if len(ct) < CT_LEN: raise ValueError("the ciphertext is %u bytes, at least %u are needed" % (len(ct), CT_LEN))

  line = "$bitgo$1*%u*%u*%s*%s*%s" % (iterations, key_size, salt.hex(), iv.hex(), ct[:CT_LEN].hex())

  return line


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash line of a BitGo wallet key for hash-mode 37231.")

  parser.add_argument("path", nargs="+", help="a file holding the key, for example a keychain or keycard as JSON, or the sjcl blob itself")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      with open(path, "r") as fd:
        found = blobs(json.load(fd))
    except json.JSONDecodeError as e:
      sys.stderr.write("%s: not JSON, %s\n" % (path, e.msg))

      rc = 1

      continue
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (path, e.strerror))

      rc = 1

      continue

    if len(found) == 0:
      sys.stderr.write("%s: no sjcl blob found\n" % path)

      rc = 1

      continue

    for blob in found:
      try:
        print(hash_line(blob))
      except ValueError as e:
        sys.stderr.write("%s: %s\n" % (path, e))

        rc = 1

  return rc


if __name__ == "__main__":
  sys.exit(main())
