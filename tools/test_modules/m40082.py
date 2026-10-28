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
    'normal': {'ci_seconds': {'opt': 1, 'pure': 54, 'bridge': 2, 'edge': 221}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 46, 'edge': 228},
    },
  }


# SAP CODVN H (PWDSALTEDHASH) iSSHA-384: like 40081 but SHA-384, so the stored blob is the final
# 48 byte digest followed by the salt, and the default iteration count is 5000.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  it = 5000 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")
  buf = salt_bytes

  for _ in range(it):
    buf = hashlib.sha384(word + buf).digest()

  return "{x-isSHA384, %d}%s" % (it, base64.b64encode(buf + salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("{x-isSHA384, "):
    return None

  end = hash_in.find("}", 13)

  if end < 0:
    return None

  iterations = int(hash_in[13:end])
  salt = base64.b64decode(hash_in[end + 1:])[48:].decode("latin-1")

  return (module_generate_hash(word, salt, iterations), word)
