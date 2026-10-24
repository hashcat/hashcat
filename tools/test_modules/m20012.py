#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import diskcryptor
from lib.test_helpers import runtime_iterations


# DiskCryptor with a 1024 bit key: up to two ciphers, so four 256 bit keys. A cascade takes its
# data keys from the front half and its tweak keys from the back half.

CASCADES = (
  (("aes",     0, 1),),
  (("twofish", 0, 1),),
  (("serpent", 0, 1),),
  (("twofish", 0, 2), ("aes",     1, 3)),
  (("serpent", 0, 2), ("twofish", 1, 3)),
  (("aes",     0, 2), ("serpent", 1, 3)),
)

KEY_COUNT = 4

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [128, 128],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 1000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None, data=None):
  return diskcryptor.generate_hash(CASCADES, KEY_COUNT, word, salt, data, iterations=ITERATIONS)


def module_verify_hash(line):
  return diskcryptor.verify_hash(CASCADES, KEY_COUNT, line, iterations=ITERATIONS)
