#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# Oracle 11g+: the salt is 10 bytes, written as 20 hex characters.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 30],
        'salt_length': [20, 20],
      },
      'optimized': {
        'password_length': [0, 30],
        'salt_length': [20, 20],
      },
      'combined_length': [20, 55],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha1(word + bytes.fromhex(salt)).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
