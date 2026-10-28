#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Placeholder mode 74000: sha256(salt.pass) then 10000 more rounds of sha256, digest*salt.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [16, 16],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha256(salt.encode() + word).digest()

  for _ in range(10000):
    digest = hashlib.sha256(digest).digest()

  return "%s*%s" % (digest.hex(), salt)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("*")

  if len(fields) < 2:
    return None

  return (module_generate_hash(word, fields[1]), word)
