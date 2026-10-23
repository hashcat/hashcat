#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string, test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (2, 16)},
  }


# GRUB 2: PBKDF2-HMAC-SHA512 with a 64 byte salt, all in hex.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40019)

NORMAL_ITERATIONS = 1024
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

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
