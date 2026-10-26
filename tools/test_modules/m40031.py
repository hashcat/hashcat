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
    'normal': {'parameters': {'iterations': 1000}, 'ci_seconds': {'opt': 1, 'pure': 24, 'bridge': 2, 'edge': 96}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 34, 'edge': 76},
    },
  }


# PBKDF2-HMAC-MD5: md5:iterations:base64(salt):base64(key), see lib/pbkdf2_b64.py.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, out_len=32):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  return pbkdf2_b64.generate_hash("md5", "md5", word, salt, iterations, out_len)


def module_verify_hash(line):
  parsed = pbkdf2_b64.parse("md5", line)

  if parsed is None:
    return None

  salt, iterations, out_len, word = parsed

  return (module_generate_hash(word, salt, iterations, out_len), word)
