#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# AxCrypt in-memory SHA1: the first 32 hex characters of SHA-1, or all 40.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, length=32):
  return "$axcrypt_sha1$" + hashlib.sha1(word).hexdigest()[:length]


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 3 or data[1] != "axcrypt_sha1" or len(data[2]) not in (32, 40):
    return None

  return (module_generate_hash(word, None, None, len(data[2])), word)
