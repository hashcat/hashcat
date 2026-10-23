#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations, iteration_override_enabled


def module_reduced_iteration_constraints():
  return {
    'runtime_limits': {'iterations': (1, 16)},
  }


# Draytek/OpenLDAP-style: 5, the 32 byte salt in hex, then PBKDF2-HMAC-SHA256 (2500 rounds).

NORMAL_ITERATIONS = 2500
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), ITERATIONS, 32)

  return "5%s%s" % (salt, digest.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("5"):
    return None

  try:
    return (module_generate_hash(word, hash_in[1:65]), word)
  except ValueError:
    return None
