#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word


def module_test_properties():
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
    'normal': {'ci_seconds': {'bridge': 2, 'pure': 118, 'opt': 88, 'edge': 167}},
  }


def module_generate_hash(word, salt, iterations=None):
  return hashlib.sha1(hashlib.md5(word).hexdigest().encode()).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
