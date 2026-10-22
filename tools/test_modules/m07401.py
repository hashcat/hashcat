#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import shacrypt

# MySQL $A$ (sha256crypt): the SHA-crypt construction with cost * 1000 rounds, the salt and the
# crypt text both written out in hex, upper case unless the line had it lower.

ITERATION_MULTIPLIER = 1000


def sha256(data):
  return hashlib.sha256(data).digest()


def module_constraints():
  return [[0, 256], [20, 20], [0, 15], [20, 20], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, lower=False):
  cost = 5 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  digest = shacrypt.crypt_bin(sha256, 256, word, salt_bytes, cost * ITERATION_MULTIPLIER).encode()

  salt_hex, dgst_hex = salt_bytes.hex(), digest.hex()

  if not lower:
    salt_hex, dgst_hex = salt_hex.upper(), dgst_hex.upper()

  return "$mysql$A$%03d*%s*%s" % (cost, salt_hex, dgst_hex)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith("$mysql$A$") or hash_in.find("*") != 12 or hash_in.find("*", 13) != 53:
    return None

  cost = int(hash_in[9:12]) if hash_in[9:12].isdigit() else 0

  if cost < 1:
    return None

  try:
    salt = bytes.fromhex(hash_in[13:53]).decode("latin-1")
  except ValueError:
    return None

  digest = hash_in[54:]

  return (module_generate_hash(word, salt, cost, digest.upper() != digest), word)
