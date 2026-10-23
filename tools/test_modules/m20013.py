#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import diskcryptor
from lib.test_helpers import iteration_override_enabled, runtime_iterations


def module_reduced_iteration_constraints():
  return {
    'runtime_limits': {'iterations': (1, 16)},
  }


# DiskCryptor with a 1536 bit key: up to three ciphers, so six 256 bit keys.

CASCADES = (
  (("aes",     0, 1),),
  (("twofish", 0, 1),),
  (("serpent", 0, 1),),
  (("twofish", 0, 2), ("aes",     1, 3)),
  (("serpent", 0, 2), ("twofish", 1, 3)),
  (("aes",     0, 2), ("serpent", 1, 3)),
  (("serpent", 0, 3), ("twofish", 1, 4), ("aes", 2, 5)),
)

KEY_COUNT = 6

NORMAL_ITERATIONS = diskcryptor.ITERATIONS
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, data=None):
  return diskcryptor.generate_hash(CASCADES, KEY_COUNT, word, salt, data, iterations=ITERATIONS)


def module_verify_hash(line):
  return diskcryptor.verify_hash(CASCADES, KEY_COUNT, line, iterations=ITERATIONS)
