#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# AxCrypt in-memory SHA1: the first 32 hex characters of SHA-1, or all 40.


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


def module_generate_hash(word, salt, iterations=None, length=32):
  return "$axcrypt_sha1$" + hashlib.sha1(word).hexdigest()[:length]


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 3 or data[1] != "axcrypt_sha1" or len(data[2]) not in (32, 40):
    return None

  return (module_generate_hash(word, None, None, len(data[2])), word)
