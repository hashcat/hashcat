#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import kernel_charset, random_bytes, random_number, split_hash_salt_word, utf16le

# PeopleSoft PS_TOKEN: SHA-1 over the token and the UTF-16LE password, which the two kernel families
# convert differently, see kernel_charset (). The token is random bytes of a random length, not a
# valid PS_TOKEN but a better test for it.

CHARSET = kernel_charset()


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 16],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  if not salt:
    salt = random_bytes(random_number(16, 255)).hex()

  digest = hashlib.sha1(bytes.fromhex(salt) + utf16le(word, CHARSET)).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
