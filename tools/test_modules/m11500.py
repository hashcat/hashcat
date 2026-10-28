#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import zlib

from lib.test_helpers import split_hash_salt_word

# CRC32 with a chosen initial value: zlib.crc32 continues from the salt (as a 32 bit seed), which is
# the same convention Digest::CRC uses with init and the final complement.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [8, 8],
      },
      'optimized': {
        'password_length': [0, 31],
        'salt_length': [8, 8],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return "%08x:%s" % (zlib.crc32(word, int(salt, 16)), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
