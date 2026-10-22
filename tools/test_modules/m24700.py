#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Stuffit5: the first 5 bytes of md5 of the first 5 bytes of md5 of the password.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return hashlib.md5(hashlib.md5(word).digest()[:5]).digest()[:5].hex()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
