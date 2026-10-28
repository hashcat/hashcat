#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# sha1(md5(md5($pass))).


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  inner = hashlib.md5(hashlib.md5(word).hexdigest().encode()).hexdigest().encode()

  return hashlib.sha1(inner).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
