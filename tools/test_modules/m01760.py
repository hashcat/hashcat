#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_salt_word


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [0, 55],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  digest = hmac.new(salt_bytes, word, hashlib.sha512).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
