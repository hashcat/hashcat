#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# FortiGate (FortiOS): AK1, then base64 of the 12 byte salt and SHA-1 over the salt, the password
# and a fixed magic.

MAGIC = bytes.fromhex("a388ba2e424cb04a537930c13107cc3fa1329029a9815b70")


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [24, 24],
      },
      'optimized': {
        'password_length': [0, 19],
        'salt_length': [24, 24],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  digest = hashlib.sha1(salt_bin + word + MAGIC).digest()

  return "AK1" + base64.b64encode(salt_bin + digest).decode()


def module_verify_hash(line):
  if line.find(b":") != 47:
    return None

  parts = split_hash_word(line)

  hash_in, word = parts

  try:
    salt = base64.b64decode(hash_in[3:])[:12].hex()
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt), word)
