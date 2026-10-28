#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import murmur
from lib.test_helpers import split_hash_word

# MurmurHash64A with a zero seed, the full 64 bit digest big endian.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 64],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return "%016x" % murmur.murmur64a(word, 0)


def module_verify_hash(line):
  parts = line.split(b":", 1)

  if len(parts) < 2 or len(parts[0]) != 16:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
