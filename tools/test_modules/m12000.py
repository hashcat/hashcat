#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pbkdf2_b64
from lib.test_helpers import random_number

# PBKDF2-HMAC-SHA1: sha1:iterations:base64(salt):base64(key), a 16 byte key and a random iteration
# count, see lib/pbkdf2_b64.py.


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = random_number(100, 10000) if iterations is None else int(iterations)

  return pbkdf2_b64.generate_hash("sha1", "sha1", word, salt, iterations, 16)


def module_verify_hash(line):
  parsed = pbkdf2_b64.parse("sha1", line)

  if parsed is None:
    return None

  salt, iterations, _, word = parsed

  return (module_generate_hash(word, salt, iterations), word)
