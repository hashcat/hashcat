#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# {SSHA512}: base64 of the 64 byte digest followed by the salt.


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 55], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  digest = hashlib.sha512(word + salt_bytes).digest()

  return "{SSHA512}" + base64.b64encode(digest + salt_bytes).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{SSHA512}"):
    return None

  try:
    raw = base64.b64decode(hash_in[9:])
  except binascii.Error:
    return None

  return (module_generate_hash(word, raw[64:].decode("latin-1")), word)
