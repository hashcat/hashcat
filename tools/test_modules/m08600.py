#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import lotus
from lib.test_helpers import split_hash_word

# Lotus Notes/Domino 5, the unsalted account hash: the domino big md of the password, see lib/lotus.py.


def module_constraints():
  return [[0, 16], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return bytes(lotus.big_md(list(word))).hex()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
