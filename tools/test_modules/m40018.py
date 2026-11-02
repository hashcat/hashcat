#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string

# macOS v10.8+: PBKDF2-HMAC-SHA512 with a 32 byte salt, all in hex.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 1024 if iterations is None else int(iterations)

  if not salt:
    salt = random_hex_string(64)

  digest = hashlib.pbkdf2_hmac("sha512", word, bytes.fromhex(salt), iterations).hex()

  return "$ml$%d$%s$%s" % (iterations, salt, digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split("$")

  if len(fields) < 5:
    return None

  iterations, salt = fields[2], fields[3]

  if not iterations.isdigit() or int(iterations) < 1:
    return None

  try:
    return (module_generate_hash(word, salt, iterations), word)
  except ValueError:
    return None
