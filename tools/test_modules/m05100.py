#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Half MD5: 16 hex characters out of the digest, the first, middle or last half.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None, idx=0):
  return hashlib.md5(word).hexdigest()[idx:idx + 16]


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  for idx in (0, 8, 16):
    new_hash = module_generate_hash(word, None, None, idx)

    if new_hash == hash_in:
      return (new_hash, word)

  return ("invalid", word)
