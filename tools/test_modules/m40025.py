#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import random_bytes, split_hash_word

# RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256): base64 of the iteration count as 4 big endian bytes, the
# 64 byte salt and a 256 byte key.


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 8192 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1") if salt else random_bytes(16)

  raw = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, 256)

  return "{PBKDF2_SHA256}" + base64.b64encode(iterations.to_bytes(4, "big") + salt_bytes + raw).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{PBKDF2_SHA256}"):
    return None

  try:
    raw = base64.b64decode(hash_in[15:])
  except binascii.Error:
    return None

  return (module_generate_hash(word, raw[4:68].decode("latin-1"), int.from_bytes(raw[:4], "big")), word)
