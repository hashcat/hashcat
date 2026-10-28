#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 40],
        'salt_length': [4, 192],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 15000}, 'ci_seconds': {'opt': 1, 'pure': 65, 'bridge': 2, 'edge': 247}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 39, 'edge': 164},
    },
  }


# SAP CODVN H isSHA512: iterations of sha512 over the password and the running digest, starting from
# the salt, then base64 of the digest and the salt.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  digest = salt_bytes

  for _ in range(iterations):
    digest = hashlib.sha512(word + digest).digest()

  return "{x-isSHA512, %d}%s" % (iterations, base64.b64encode(digest + salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{x-isSHA512, "):
    return None

  idx = hash_in.find("}", 13)

  if idx < 1 or not hash_in[13:idx].isdigit():
    return None

  try:
    salt = base64.b64decode(hash_in[idx + 1:])[64:].decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, hash_in[13:idx]), word)
