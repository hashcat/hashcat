#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

from lib.test_helpers import iteration_override_enabled, runtime_iterations


def module_reduced_iteration_constraints():
  return {
    'runtime_limits': {'iterations': (1, 16)},
  }


# NetIQ SSPR (Salted SHA512): 1000 rounds, a 16 character salt, see lib/sspr.py.

NORMAL_ITERATIONS = 1000
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(4, hashlib.sha512, NORMAL_ITERATIONS, word, salt, effective_iterations=ITERATIONS)


def module_verify_hash(line):
  parsed = sspr.parse(4, NORMAL_ITERATIONS, line)

  if parsed is None or len(parsed[0]) != 16:
    return None

  return (module_generate_hash(parsed[1], parsed[0]), parsed[1])
