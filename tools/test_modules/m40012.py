#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Cisco-ISE: SHA-256 over the 32 byte salt and the password, then 128 more rounds of it, followed
# by the salt in hex.


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha256(bytes.fromhex(salt) + word).digest()

  for _ in range(128):
    digest = hashlib.sha256(digest).digest()

  return digest.hex() + salt


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if len(hash_in) // 2 != 64:
    return None

  try:
    return (module_generate_hash(word, hash_in[64:]), word)
  except ValueError:
    return None
