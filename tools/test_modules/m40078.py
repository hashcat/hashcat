#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word, test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (2, 16)},
  }


# SAP CODVN H isSHA512: iterations of sha512 over the password and the running digest, starting from
# the salt, then base64 of the digest and the salt.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40078)

NORMAL_ITERATIONS = 15000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 40], [4, 192], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

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
