#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# blake2b512($salt.$pass).


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 127],
        'salt_length': [0, 127],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [0, 55],
      },
      'combined_length': [0, 55],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return "$BLAKE2$%s:%s" % (hashlib.blake2b(salt.encode() + word).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
