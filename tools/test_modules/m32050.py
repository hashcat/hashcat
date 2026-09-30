#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# PBKDF2-HMAC-SHA1, 100000 rounds: $pbkdf2-hmac-sha1$100000$<salt hex>$<key hex>, the 32 byte salt.


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, 100000, 20)

  return "$pbkdf2-hmac-sha1$100000$%s$%s" % (salt_bin.hex(), key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$pbkdf2-hmac-sha1$100000$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 4 or len(fields[3]) != 64:
    return None

  try:
    return (module_generate_hash(word, fields[3]), word)
  except ValueError:
    return None
