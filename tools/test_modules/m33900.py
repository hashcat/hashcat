#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Draytek/OpenLDAP-style: 5, the 32 byte salt in hex, then PBKDF2-HMAC-SHA256 (2500 rounds).


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), 2500, 32)

  return "5%s%s" % (salt, digest.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("5"):
    return None

  try:
    return (module_generate_hash(word, hash_in[1:65]), word)
  except ValueError:
    return None
