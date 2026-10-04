#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# SAP CODVN H (PWDSALTEDHASH) iSSHA-256: {x-isSHA256, iter}base64(sha256 iterated over word.buf . salt).
# The buffer starts at the salt and each round is sha256(word . buffer); the stored blob is the final
# 32 byte digest followed by the salt.


def module_constraints():
  return [[0, 40], [4, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  it = 3000 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")
  buf = salt_bytes

  for _ in range(it):
    buf = hashlib.sha256(word + buf).digest()

  return "{x-isSHA256, %d}%s" % (it, base64.b64encode(buf + salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{x-isSHA256, "):
    return None

  end = hash_in.find("}", 13)

  if end < 0:
    return None

  iterations = int(hash_in[13:end])
  salt = base64.b64decode(hash_in[end + 1:])[32:].decode("latin-1")

  return (module_generate_hash(word, salt, iterations), word)
