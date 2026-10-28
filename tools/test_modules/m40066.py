#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations


# PBKDF2-HMAC-SHA512, 100000 rounds: $pbkdf2-hmac-sha512$100000.<salt hex>.<key hex>, dot separated.

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
    'normal': {'parameters': {'iterations': 100000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha512", word, salt_bin, ITERATIONS, 64)

  return "$pbkdf2-hmac-sha512$100000.%s.%s" % (salt_bin.hex(), key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$pbkdf2-hmac-sha512$100000."):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")[2].split(".")

  if len(fields) < 3 or len(fields[1]) != 64:
    return None

  try:
    return (module_generate_hash(word, fields[1]), word)
  except ValueError:
    return None
