#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# BLAKE2s-256.


def module_constraints():
  return [[0, 128], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return "$BLAKE2$" + hashlib.blake2s(word).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
