#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 40],
        'salt_length': [4, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'ci_seconds': {'opt': 1, 'pure': 45, 'bridge': 2, 'edge': 171}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 46, 'edge': 169},
    },
  }


# SAP CODVN H (PWDSALTEDHASH) iSSHA-256: {x-isSHA256, iter}base64(sha256 iterated over word.buf . salt).
# The buffer starts at the salt and each round is sha256(word . buffer); the stored blob is the final
# 32 byte digest followed by the salt.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  it = 3000 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")
  buf = salt_bytes

  for _ in range(it):
    buf = hashlib.sha256(word + buf).digest()

  return "{x-isSHA256, %d}%s" % (it, base64.b64encode(buf + salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{x-isSHA256, "):
    return None

  end = hash_in.find("}", 13)

  if end < 0:
    return None

  iterations = int(hash_in[13:end])
  salt = base64.b64decode(hash_in[end + 1:])[32:].decode("latin-1")

  return (module_generate_hash(word, salt, iterations), word)
