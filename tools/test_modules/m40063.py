#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

from lib.test_helpers import runtime_iterations


# NetIQ SSPR (Salted SHA512): 1000 rounds, a 16 character salt, see lib/sspr.py.

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
    'normal': {'parameters': {'iterations': 1000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(4, hashlib.sha512, ITERATION_DEFAULTS['iterations'], word, salt, effective_iterations=ITERATIONS)


def module_verify_hash(line):
  parsed = sspr.parse(4, ITERATION_DEFAULTS['iterations'], line)

  if parsed is None or len(parsed[0]) != 16:
    return None

  return (module_generate_hash(parsed[1], parsed[0]), parsed[1])
