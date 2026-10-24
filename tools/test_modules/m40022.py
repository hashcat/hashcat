#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (2, 16)},
  }


# Django (PBKDF2-SHA256): pbkdf2_sha256$iterations$salt$base64.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40022)

NORMAL_ITERATIONS = 10000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [0, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  raw = hashlib.pbkdf2_hmac("sha256", word, salt.encode(), iterations)

  return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt, base64.b64encode(raw).decode())


def module_verify_hash(line):
  if not line.startswith(b"pbkdf2_sha256$"):
    return None

  fields = line[14:].split(b"$", 2)

  if len(fields) != 3:
    return None

  idx = fields[2].find(b":")

  if idx < 1:
    return None

  try:
    return (module_generate_hash(fields[2][idx + 1:], fields[1].decode(), fields[0].decode()), fields[2][idx + 1:])
  except ValueError:
    return None
