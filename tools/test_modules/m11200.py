#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# MySQL CRAM (SHA1): sha1(pass) XOR sha1(salt.sha1(sha1(pass))), the 20 byte salt in hex.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [40, 40],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [40, 40],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  sha1_pass = hashlib.sha1(word).digest()

  xor_part2 = hashlib.sha1(bytes.fromhex(salt) + hashlib.sha1(sha1_pass).digest()).digest()

  digest = bytes(a ^ b for a, b in zip(sha1_pass, xor_part2)).hex()

  return "$mysqlna$%s*%s" % (salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) < 3 or data[1] != "mysqlna":
    return None

  try:
    return (module_generate_hash(word, data[2].split("*")[0]), word)
  except ValueError:
    return None
