#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# SAP CODVN H (PWDSALTEDHASH) iSSHA-384: like 37300 but SHA-384, so the stored blob is the final
# 48 byte digest followed by the salt, and the default iteration count is 5000.


def module_constraints():
  return [[0, 40], [4, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  it = 5000 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")
  buf = salt_bytes

  for _ in range(it):
    buf = hashlib.sha384(word + buf).digest()

  return "{x-isSHA384, %d}%s" % (it, base64.b64encode(buf + salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{x-isSHA384, "):
    return None

  end = hash_in.find("}", 13)

  if end < 0:
    return None

  iterations = int(hash_in[13:end])
  salt = base64.b64decode(hash_in[end + 1:])[48:].decode("latin-1")

  return (module_generate_hash(word, salt, iterations), word)
