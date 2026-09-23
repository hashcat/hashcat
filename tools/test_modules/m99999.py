#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_word

# Plaintext (mode 99999): the hash string is the plaintext itself, so the oracle is the identity
# function. module_hash_decode stores the line verbatim and derives an MD4 digest from it, one block,
# which caps the length at 55. The compare harness' "invalid input" check cannot be met here and is
# not meant to be: with the hash equal to the plaintext there is no such thing as an invalid hash,
# so both engines accept the same lines. The perl oracle behaves identically.


def module_constraints():
  return [[1, 55], [-1, -1], [1, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  return word.decode("utf-8")


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  return (module_generate_hash(word), word)
