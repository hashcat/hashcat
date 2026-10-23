#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import diskcryptor
from lib.test_helpers import iteration_override_enabled, runtime_iterations

# DiskCryptor with a 512 bit key: one cipher, so two 256 bit keys, one for the data and one for
# the tweak.

CASCADES = (
  (("aes",     0, 1),),
  (("twofish", 0, 1),),
  (("serpent", 0, 1),),
)

KEY_COUNT = 2

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
