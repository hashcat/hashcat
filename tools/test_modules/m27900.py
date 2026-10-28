#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_salt_word

# CRC32C (Castagnoli) with a chosen initial value, the same zlib convention as CRC32: the register
# starts at seed ^ 0xffffffff and the result is complemented.

POLY = 0x82f63b78


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
  crc = int(salt, 16) ^ 0xffffffff

  for b in word:
    crc ^= b

    for _ in range(8):
      crc = (crc >> 1) ^ (POLY if (crc & 1) else 0)

  return "%08x:%s" % (crc ^ 0xffffffff, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
