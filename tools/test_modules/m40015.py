#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import aix

from lib.test_helpers import test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (0, 4)},
  }


# AIX {ssha256}: PBKDF2-HMAC-SHA256, see lib/aix.py.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40015)


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 64 if iterations is None else 1 << int(iterations)

  return aix.generate_hash("ssha256", "sha256", word, salt, iterations)


def module_verify_hash(line):
  return aix.verify_hash("ssha256", "sha256", line)
