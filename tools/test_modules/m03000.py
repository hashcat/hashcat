#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.des_key import setup_des_key
from lib.test_helpers import split_hash_word

# LM: DES of KGS!@#$% keyed with the upper cased password, zero padded. The password is at most 7
# characters here, so the first half is the whole hash.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [1, 7],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  key = (word.upper() + b"\x00" * 14)[:7]

  return DES.new(setup_des_key(key), DES.MODE_ECB).encrypt(b"KGS!@#$%").hex()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
