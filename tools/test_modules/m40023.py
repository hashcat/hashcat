#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# SAP CODVN H (PWDSALTEDHASH) iSSHA-1: SHA-1 of the password and the last digest, starting from the
# salt, then base64 of the digest and the salt.


def module_constraints():
  return [[0, 40], [4, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 1024 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  digest = salt_bytes

  for _ in range(iterations):
    digest = hashlib.sha1(word + digest).digest()

  return "{x-issha, %d}%s" % (iterations, base64.b64encode(digest + salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{x-issha, "):
    return None

  idx = hash_in.find("}", 10)

  if idx < 1 or not hash_in[10:idx].isdigit():
    return None

  try:
    salt = base64.b64decode(hash_in[idx + 1:])[20:].decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, hash_in[10:idx]), word)
