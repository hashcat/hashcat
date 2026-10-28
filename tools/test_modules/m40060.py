#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib import sspr

from lib.test_helpers import runtime_iterations


# NetIQ SSPR (Salted SHA256): 100000 rounds, a 24 byte salt in base64, see lib/sspr.py.

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [24, 24],
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
  return sspr.generate_hash(3, hashlib.sha256, ITERATION_DEFAULTS['iterations'], word, base64.b64encode(salt.encode("latin-1")).decode(), effective_iterations=ITERATIONS)


def module_verify_hash(line):
  parsed = sspr.parse(3, ITERATION_DEFAULTS['iterations'], line)

  if parsed is None or len(parsed[0]) != 32:
    return None

  try:
    salt = base64.b64decode(parsed[0])
  except binascii.Error:
    return None

  if len(salt) != 24:
    return None

  return (module_generate_hash(parsed[1], salt.decode("latin-1")), parsed[1])
