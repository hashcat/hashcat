#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# MySQL4.1/MySQL5: sha1(sha1_bin($pass)), without MySQL's leading * and in lower case.


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


def module_generate_hash(word, salt, iterations=None):
  return hashlib.sha1(hashlib.sha1(word).digest()).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
