#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# MSSQL (2005): the password in UTF-16LE, then the 4 byte salt. The two kernel families convert the
# password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [8, 8],
      },
      'optimized': {
        'password_length': [0, 27],
        'salt_length': [8, 8],
      },
      'combined_length': [8, 27],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  wide = utf16le(word, CHARSET)

  digest = hashlib.sha1(wide + bytes.fromhex(salt)).hexdigest()

  return "0x0100%s%s" % (salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    return (module_generate_hash(word, hash_in[6:14]), word)
  except ValueError:
    return None
