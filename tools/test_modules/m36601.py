#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import kernel_charset, split_hash_word, utf16le, runtime_iterations


# PBKDF2-HMAC-SHA512 over a UTF-16LE password with a 4 byte salt, 100000 iterations:
# 0x0300 <salt hex> <64 byte key hex>. The optimized kernels widen each password byte instead of
# decoding UTF-8, so the oracle picks its charset from IS_OPTIMIZED, matching module_01000.

CHARSET = kernel_charset()

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [8, 8],
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
  digest = hashlib.pbkdf2_hmac("sha512", utf16le(word, CHARSET), bytes.fromhex(salt), ITERATIONS, 64)

  return "0x0300%s%s" % (salt, digest.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    return (module_generate_hash(word, hash_in[6:14]), word)
  except ValueError:
    return None
