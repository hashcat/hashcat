#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# hMailServer: a 6 character salt, then the digest.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [6, 6],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [6, 6],
      },
      'combined_length': [6, 55],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return salt + hashlib.sha256(salt.encode() + word).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if len(hash_in) != 70:
    return None

  return (module_generate_hash(word, hash_in[:6]), word)
