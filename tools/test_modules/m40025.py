#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import random_bytes, split_hash_word, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [64, 64],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 8192}, 'ci_seconds': {'opt': 1, 'pure': 30, 'bridge': 3, 'edge': 80}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 37, 'edge': 141},
    },
  }


# RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256): base64 of the iteration count as 4 big endian bytes, the
# 64 byte salt and a 256 byte key.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1") if salt else random_bytes(16)

  raw = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, 256)

  return "{PBKDF2_SHA256}" + base64.b64encode(iterations.to_bytes(4, "big") + salt_bytes + raw).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{PBKDF2_SHA256}"):
    return None

  try:
    raw = base64.b64decode(hash_in[15:])
  except binascii.Error:
    return None

  return (module_generate_hash(word, raw[4:68].decode("latin-1"), int.from_bytes(raw[:4], "big")), word)
