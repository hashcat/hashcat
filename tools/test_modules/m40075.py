#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations


# Draytek/OpenLDAP-style: 5, the 32 byte salt in hex, then PBKDF2-HMAC-SHA256 (2500 rounds).

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [64, 64],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 2500}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), ITERATIONS, 32)

  return "5%s%s" % (salt, digest.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("5"):
    return None

  try:
    return (module_generate_hash(word, hash_in[1:65]), word)
  except ValueError:
    return None
