#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pbkdf2_b64

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [1, 15],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 1000}, 'ci_seconds': {'opt': 1, 'pure': 39, 'bridge': 2, 'edge': 100}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 41, 'edge': 163},
    },
  }


# PBKDF2-HMAC-SHA256: sha256:iterations:base64(salt):base64(key), see lib/pbkdf2_b64.py.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, out_len=24):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  return pbkdf2_b64.generate_hash("sha256", "sha256", word, salt, iterations, out_len)


def module_verify_hash(line):
  parsed = pbkdf2_b64.parse("sha256", line)

  if parsed is None:
    return None

  salt, iterations, out_len, word = parsed

  return (module_generate_hash(word, salt, iterations, out_len), word)
