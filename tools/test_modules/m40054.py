#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

# FortiGate 256 (FortiOS): sha256 over the salt, the password and a fixed magic, prefixed with the
# salt and base64 encoded, behind the "SH2" signature.

SIGNATURE = "SH2"
MAGIC = bytes.fromhex("a388ba2e424cb04a537930c13107cc3fa1329029a9815b70")


def module_constraints():
  return [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  hash_buf = hashlib.sha256(salt_bin + word + MAGIC).digest()

  return SIGNATURE + base64.b64encode(salt_bin + hash_buf).decode("ascii")


def module_verify_hash(line):
  idx = line.find(b":")

  if idx != 63:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  try:
    decoded = base64.b64decode(hash_in[3:])
  except Exception:
    return None

  salt = decoded[:12].hex()

  return (module_generate_hash(word, salt), word)
