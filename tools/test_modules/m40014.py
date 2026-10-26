#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_salt_word

# HMAC-RIPEMD160 keyed with the salt (perl hmac (data = password, key = salt)).


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
  digest = hmac.new(salt.encode(), word, lambda d=b"": hashlib.new("ripemd160", d)).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
