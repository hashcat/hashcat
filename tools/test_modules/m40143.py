#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import hamsi
from lib.test_helpers import split_hash_word

# Hamsi-384, see lib/hamsi.py.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return hamsi.hamsi384(word).hex()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
