#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from pygost import gost341194

from lib.test_helpers import split_hash_word

# GOST R 34.11-94, the test parameter S box, which is what perl's Digest::GOST uses.


def module_constraints():
  return [[-1, -1], [-1, -1], [1, 32], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return gost341194.GOST341194(word, sbox="id-GostR3411-94-TestParamSet").hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
