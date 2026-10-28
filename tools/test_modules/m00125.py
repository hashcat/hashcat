#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# ArubaOS: 4 byte salt in hex, the signature byte 01, then the digest over both and the password.

SIGNATURE = "01"


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 253],
        'salt_length': [8, 8],
      },
      'optimized': {
        'password_length': [0, 53],
        'salt_length': [8, 8],
      },
      'combined_length': [8, 53],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha1(bytes.fromhex(salt + SIGNATURE) + word).hexdigest()

  return salt + SIGNATURE + digest


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    return (module_generate_hash(word, hash_in[:8]), word)
  except ValueError:
    return None
