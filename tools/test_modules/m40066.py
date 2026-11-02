#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# PBKDF2-HMAC-SHA512, 100000 rounds: $pbkdf2-hmac-sha512$100000.<salt hex>.<key hex>, dot separated.


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha512", word, salt_bin, 100000, 64)

  return "$pbkdf2-hmac-sha512$100000.%s.%s" % (salt_bin.hex(), key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$pbkdf2-hmac-sha512$100000."):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")[2].split(".")

  if len(fields) < 3 or len(fields[1]) != 64:
    return None

  try:
    return (module_generate_hash(word, fields[1]), word)
  except ValueError:
    return None
