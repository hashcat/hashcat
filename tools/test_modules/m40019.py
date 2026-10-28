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
    'normal': {'parameters': {'iterations': 1024}, 'ci_seconds': {'opt': 1, 'pure': 30, 'bridge': 2, 'edge': 147}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 44, 'edge': 107},
    },
  }


# GRUB 2: PBKDF2-HMAC-SHA512 with a 64 byte salt, all in hex.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  if not salt:
    salt = random_hex_string(128)

  digest = hashlib.pbkdf2_hmac("sha512", word, bytes.fromhex(salt), iterations).hex()

  return "grub.pbkdf2.sha512.%d.%s.%s" % (iterations, salt, digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split(".")

  if len(fields) < 6 or not fields[3].isdigit():
    return None

  iterations, salt = fields[3], fields[4]

  try:
    return (module_generate_hash(word, salt, iterations), word)
  except ValueError:
    return None
