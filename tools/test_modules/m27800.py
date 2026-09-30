#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import murmur
from lib.test_helpers import split_hash_salt_word

# MurmurHash3 32-bit, big endian seed and digest.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 55], [8, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  seed = int.from_bytes(bytes.fromhex(salt), "big")

  return "%08x:%s" % (murmur.murmur3_32(word, seed), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
