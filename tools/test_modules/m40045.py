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
        'salt_length': [0, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 1000}, 'ci_seconds': {'opt': 1, 'pure': 52, 'bridge': 2, 'edge': 206}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 70, 'edge': 206},
    },
  }


# Oracle Transportation Management (SHA256): SHA-256 of the salt and the password, then of the
# digest, iterations times in all.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  digest = hashlib.sha256(salt.encode() + word).digest()

  for _ in range(1, iterations):
    digest = hashlib.sha256(digest).digest()

  return "otm_sha256:%d:%s:%s" % (iterations, salt, base64.b64encode(digest).decode())


def module_verify_hash(line):
  parts = line.split(b":", 4)

  if len(parts) != 5 or not parts[1].isdigit():
    return None

  _, iterations, salt, _, word = parts

  return (module_generate_hash(word, salt.decode(), iterations), word)
