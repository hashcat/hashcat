#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 15],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 10000}, 'ci_seconds': {'opt': 1, 'pure': 35, 'bridge': 2, 'edge': 131}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 2, 'pure': 30, 'edge': 163},
    },
  }


# Django (PBKDF2-SHA256): pbkdf2_sha256$iterations$salt$base64.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

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
