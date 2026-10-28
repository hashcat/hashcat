#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import murmur
from lib.test_helpers import split_hash_salt_word

# MurmurHash3 32-bit, big endian seed and digest.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': None,
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [8, 8],
      },
      'combined_length': None,
    },
  }


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
