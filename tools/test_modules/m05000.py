#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 127],
      },
      'optimized': {
        'password_length': [0, 27],
        'salt_length': [0, 27],
      },
      'combined_length': [0, 27],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  digest = hashlib.sha1(hashlib.sha1(salt_bytes + word + salt_bytes).hexdigest().encode()).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
