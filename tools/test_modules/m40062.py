#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib import sspr

from lib.test_helpers import iteration_override_enabled, runtime_iterations


def module_reduced_iteration_constraints():
  return {
    'runtime_limits': {'iterations': (1, 16)},
  }


# NetIQ SSPR (Salted SHA512): 100000 rounds, a 24 byte salt in base64, see lib/sspr.py.

NORMAL_ITERATIONS = 100000
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(4, hashlib.sha512, NORMAL_ITERATIONS, word, base64.b64encode(salt.encode("latin-1")).decode(), effective_iterations=ITERATIONS)


def module_verify_hash(line):
  parsed = sspr.parse(4, NORMAL_ITERATIONS, line)

  if parsed is None or len(parsed[0]) != 32:
    return None

  try:
    salt = base64.b64decode(parsed[0])
  except binascii.Error:
    return None

  if len(salt) != 24:
    return None

  return (module_generate_hash(parsed[1], salt.decode("latin-1")), parsed[1])
