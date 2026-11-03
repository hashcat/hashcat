#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write a hashcat hash line for a TronLink wallet keystore, for mode 30800.
#
# The keystore the wallet reads is a .txt file holding a hex encoded json object with the members
# key, address and salt. The private key is encrypted with AES-256-CTR under a 32 byte key that
# PBKDF2-HMAC-SHA512 derives from the password and the salt in a single iteration.
#
# The salt is free text rather than a hex field, so the line carries its utf-8 bytes in hex.
#
# Reference: packages/lib/utils.js and
# packages/popup/src/controllers/RestoreAccountController/stages/KeystoreImport/index.js of
# https://github.com/TronLink/tronlink-extension

import argparse
import json
import sys

CIPHERTEXT_LEN = 64
SALT_MAX       = 256


def parse_contents(data):
  # The wallet stores the json hex encoded. A file that was decoded by hand before it reached here
  # is accepted as well, because the two are easy to confuse and both carry the same members.

  try:
    text = data.decode("utf-8").strip()
  except UnicodeDecodeError:
    return (None, "the file is not utf-8 text")

  if len(text) == 0:
    return (None, "the file is empty")

  try:
    return (json.loads(text), None)
  except ValueError:
    pass

  # bytes.fromhex skips ascii whitespace and refuses an odd number of digits on its own

  try:
    raw = bytes.fromhex(text)
  except ValueError:
    return (None, "the file is neither json nor hex")

  try:
    return (json.loads(raw.decode("utf-8")), None)
  except (UnicodeDecodeError, ValueError):
    return (None, "the file is hex but does not decode to json")


def int_field(name, value):
  # A wallet may write a number or a numeric string, so int() is right. A field that is neither
  # has to be refused rather than raising out of the script.

  try:
    return (int(value), None)
  except (TypeError, ValueError):
    return (None, "%s is not a number" % name)


def keystore_to_line(j):
  # A Web3 Secret Storage keystore carries its fields under a crypto member. Several Tron tools
  # write that format instead, and it belongs to another mode.

  for name in ["crypto", "Crypto"]:
    if name in j:
      return (None, "this is a Web3 Secret Storage keystore, for hash-mode 15600 or 15700")

  for name in ["key", "salt"]:
    if name not in j:
      return (None, "no %s member, so this is not a TronLink keystore" % name)

  # The tronscan wizard writes version 1 and the wallet's reader ignores the member, so a file
  # without it is still read. A later version could change the derivation, and a line written for
  # one of those would load in mode 30800 and never crack, so a version that is present is checked.

  if "version" in j:
    version, problem = int_field("the version", j["version"])

    if problem is not None:
      return (None, problem)

    if version != 1:
      return (None, "the keystore is version %i, and this tool writes lines for version 1" % version)

  key  = j["key"]
  salt = j["salt"]

  if isinstance(key, str) == False:
    return (None, "the key is not a string")

  if isinstance(salt, str) == False:
    return (None, "the salt is not a string")

  try:
    key_bytes = bytes.fromhex(key)
  except ValueError:
    return (None, "the key is not hex")

  if len(key_bytes) != CIPHERTEXT_LEN:
    return (None, "the key is %i bytes, and a TronLink keystore holds a %i byte ciphertext, the "
                  "private key written as %i hex characters"
                  % (len(key_bytes), CIPHERTEXT_LEN, CIPHERTEXT_LEN))

  # json.loads accepts a lone surrogate, which utf-8 cannot encode

  try:
    salt_bytes = salt.encode("utf-8")
  except UnicodeEncodeError:
    return (None, "the salt is not encodable as utf-8")

  if len(salt_bytes) > SALT_MAX:
    return (None, "the salt is %i bytes, and this tool writes lines for at most %i"
                  % (len(salt_bytes), SALT_MAX))

  line = "$tronlink$%s*%s" % (salt_bytes.hex(), key_bytes.hex())

  return (line, None)


def file_to_line(path):
  try:
    with open(path, "rb") as fh:
      data = fh.read()
  except OSError as e:
    return (None, "cannot be read: %s" % e)

  j, problem = parse_contents(data)

  if problem is not None:
    return (None, problem)

  if isinstance(j, dict) == False:
    return (None, "the file is not a json object")

  return keystore_to_line(j)


def main():
  parser = argparse.ArgumentParser(description="Write hashcat hash lines for TronLink wallet "
                                               "keystore files, for mode 30800.")

  parser.add_argument("files", nargs="+", help="keystore .txt files")

  args = parser.parse_args()

  failed = 0

  for path in args.files:
    # A keystore is a file somebody downloaded, so anything this one file does has to stay with
    # this one file. Without the catch, a crafted file ends the run and the remaining paths on the
    # command line are never looked at: json.loads raises RecursionError, not ValueError, on deeply
    # nested input, and that is only the instance we know about.

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
