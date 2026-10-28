#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import kernel_charset, split_hash_salt_word, utf16le

# Windows Phone 8+ PIN/password: SHA-256 over the UTF-16LE password and the 128 byte salt. The two
# kernel families convert the password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [256, 256],
      },
      'optimized': {
        'password_length': [0, 27],
        'salt_length': [256, 256],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha256(utf16le(word, CHARSET) + bytes.fromhex(salt)).hexdigest()

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
