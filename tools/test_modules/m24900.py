#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Dahua: md5 of the password folded to eight itoa62 characters, each the sum of a pair of digest
# bytes modulo 62.

ITOA62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  digest = hashlib.md5(word).digest()

  return "".join(ITOA62[(digest[i] + digest[i + 1]) % 62] for i in range(0, 16, 2))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  return (module_generate_hash(word), word)
