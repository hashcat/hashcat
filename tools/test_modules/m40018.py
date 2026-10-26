#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string, test_iteration_parameters


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
    'normal': {'parameters': {'iterations': 1024}, 'ci_seconds': {'opt': 1, 'pure': 50, 'bridge': 2, 'edge': 240}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 34, 'edge': 238},
    },
  }


# macOS v10.8+: PBKDF2-HMAC-SHA512 with a 32 byte salt, all in hex.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  if not salt:
    salt = random_hex_string(64)

  digest = hashlib.pbkdf2_hmac("sha512", word, bytes.fromhex(salt), iterations).hex()

  return "$ml$%d$%s$%s" % (iterations, salt, digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split("$")

  if len(fields) < 5:
    return None

  iterations, salt = fields[2], fields[3]

  if not iterations.isdigit() or int(iterations) < 1:
    return None

  try:
    return (module_generate_hash(word, salt, iterations), word)
  except ValueError:
    return None
