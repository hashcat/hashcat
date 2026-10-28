#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations


# Atlassian (PBKDF2-HMAC-SHA1): {PKCS5S2} and base64 of the 16 byte salt and a 32 byte key.

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 10000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  raw = hashlib.pbkdf2_hmac("sha1", word, salt_bytes, ITERATIONS, 32)

  return "{PKCS5S2}" + base64.b64encode(salt_bytes + raw).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{PKCS5S2}"):
    return None

  try:
    raw = base64.b64decode(hash_in[9:])
  except binascii.Error:
    return None

  if len(raw) != 16 + 32:
    return None

  return (module_generate_hash(word, raw[:16].decode("latin-1")), word)
