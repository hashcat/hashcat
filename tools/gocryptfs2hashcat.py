#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a gocryptfs volume for hash-mode 37200.
#
# A gocryptfs volume keeps its key material in gocryptfs.conf at the root of the encrypted
# directory. The file is JSON and carries the scrypt parameters, the salt and EncryptedKey, which
# is the nonce, the master key wrapped with AES-256-GCM and the GCM tag, one after the other. The
# tag verifies the password on its own, which is what hash-mode 37200 checks.
#
# DroidFS volumes use the same file. A CryFS or EncFS volume does not and is not read here.

import argparse
import base64
import binascii
import json
import os
import sys

# the scrypt salt of every version 2 config

SALT_LEN = 32

# the wrapped master key and the GCM tag, which are the same size whatever the nonce is

KEY_LEN = 32
TAG_LEN = 16

# the HKDF feature flag widens the nonce from 12 bytes to 16

IV_LEN_HKDF   = 16
IV_LEN_LEGACY = 12

CONF_NAME = "gocryptfs.conf"


def conf_file(path: str) -> str:
  if os.path.isfile(path) == True: return path

  joined = os.path.join(path, CONF_NAME)

  if os.path.isfile(joined) == True: return joined

  raise ValueError("%s holds no %s" % (path, CONF_NAME))


def b64_field(obj: dict, name: str, want_len: int) -> bytes:
  if name not in obj: raise ValueError("the config has no %s" % name)

  try:
    raw = base64.b64decode(obj[name], validate=True)
  except binascii.Error:
    raise ValueError("%s is not base64" % name)

  if want_len > 0:
    if len(raw) != want_len: raise ValueError("%s is %u bytes, expected %u" % (name, len(raw), want_len))

  return raw


def hash_line(conf: dict) -> str:
  version = conf.get("Version")

  if version != 2: raise ValueError("config version %s is not supported, only 2 is" % version)

  flags = conf.get("FeatureFlags", [])

  hkdf = 1 if "HKDF" in flags else 0

  iv_len = IV_LEN_HKDF if hkdf == 1 else IV_LEN_LEGACY

  blob = b64_field(conf, "EncryptedKey", iv_len + KEY_LEN + TAG_LEN)

  scrypt_object = conf.get("ScryptObject")

  if scrypt_object is None: raise ValueError("the config has no ScryptObject")

  salt = b64_field(scrypt_object, "Salt", SALT_LEN)

  for name in ("N", "R", "P"):
    if name not in scrypt_object: raise ValueError("ScryptObject has no %s" % name)

  key_len = scrypt_object.get("KeyLen", KEY_LEN)

  if key_len != KEY_LEN: raise ValueError("a KeyLen of %s is not supported, only %u is" % (key_len, KEY_LEN))

  line = "$gocryptfs$2*%u*%u*%u*%u*%s*%s" % (
    hkdf,
    scrypt_object["N"],
    scrypt_object["R"],
    scrypt_object["P"],
    salt.hex(),
    blob.hex())

  return line


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash line of a gocryptfs volume for hash-mode 37200.")

  parser.add_argument("path", nargs="+", help="a gocryptfs.conf, or the directory holding one")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      with open(conf_file(path), "r") as fd:
        print(hash_line(json.load(fd)))
    except ValueError as e:
      sys.stderr.write("%s: %s\n" % (path, e))

      rc = 1
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (path, e.strerror))

      rc = 1

  return rc


if __name__ == "__main__":
  sys.exit(main())
