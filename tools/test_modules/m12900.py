#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_word

# Android FDE (Samsung DEK): PBKDF2-HMAC-SHA256 of the password, then HMAC-SHA256 with that key over
# a second 32 byte salt, which defaults to the first one twice.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None, salt2=None):
  if salt2 is None:
    salt2 = salt + salt

  key = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), 4096, 32)

  return salt2 + hmac.new(key, bytes.fromhex(salt2), hashlib.sha256).hexdigest() + salt


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if len(hash_in) != 160:
    return None

  try:
    return (module_generate_hash(word, hash_in[128:160], None, hash_in[:64]), word)
  except ValueError:
    return None
