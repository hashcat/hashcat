#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# WBB3 (Woltlab Burning Board): sha1($salt.sha1($salt.sha1($pass))).


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [40, 40],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [40, 40],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  s = salt.encode()

  inner = hashlib.sha1(s + hashlib.sha1(word).hexdigest().encode()).hexdigest().encode()

  return "%s:%s" % (hashlib.sha1(s + inner).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
