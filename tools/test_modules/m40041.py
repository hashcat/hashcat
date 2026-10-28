#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import re

from lib.test_helpers import random_numeric_string, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 4096}, 'ci_seconds': {'opt': 1, 'pure': 46, 'bridge': 2, 'edge': 272}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 21, 'pure': 42, 'edge': 197},
    },
  }


# QNX 7 /etc/shadow (SHA512): PBKDF2-HMAC-SHA512, 4096 rounds by default, @S@base64(key)@base64(salt),
# with "S,rounds" as the tag for any other count.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  if not salt:
    salt = random_numeric_string(16)

  salt_bytes = salt.encode("latin-1")

  key = hashlib.pbkdf2_hmac("sha512", word, salt_bytes, iterations)

  tag = "S" if iterations == 4096 else "S,%d" % iterations

  return "@%s@%s@%s" % (tag, base64.b64encode(key).decode(), base64.b64encode(salt_bytes).decode())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  parts = hash_in.split("@")

  if len(parts) < 4:
    return None

  m = re.match(r"^S,(\d+)$", parts[1])

  iterations = int(m.group(1)) if m else 4096

  if iterations < 1:
    return None

  try:
    salt = base64.b64decode(parts[3]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, iterations), word)
