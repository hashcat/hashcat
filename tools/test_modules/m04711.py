#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# Huawei sha1(md5($pass).$salt), with an 8 character salt.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [8, 8],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [8, 8],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha1(hashlib.md5(word).hexdigest().encode() + salt.encode()).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  if len(salt) != 8:
    return None

  return (module_generate_hash(word, salt), word)
