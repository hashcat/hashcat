#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

from lib.test_helpers import runtime_iterations


# NetIQ SSPR (SHA1): 100000 rounds, no salt, see lib/sspr.py.

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
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
  return sspr.generate_hash(1, hashlib.sha1, ITERATION_DEFAULTS['iterations'], word, "NONE", effective_iterations=ITERATIONS)


def module_verify_hash(line):
  parsed = sspr.parse(1, ITERATION_DEFAULTS['iterations'], line)

  if parsed is None or parsed[0] != "NONE":
    return None

  return (module_generate_hash(parsed[1], None), parsed[1])
