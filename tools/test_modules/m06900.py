#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import gost341194

from lib.test_helpers import split_hash_word

# GOST R 34.11-94, the test parameter S box, which is what perl's Digest::GOST uses.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 32],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return gost341194.hexdigest(word)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
