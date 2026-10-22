#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# The salt travels inside the base64, after the 20 byte digest.


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 55], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  digest = hashlib.sha1(word + salt_bytes).digest()

  return "{SSHA}" + base64.b64encode(digest + salt_bytes).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{SSHA}"):
    return None

  try:
    raw = base64.b64decode(hash_in[6:])
  except binascii.Error:
    return None

  return (module_generate_hash(word, raw[20:].decode("latin-1")), word)
