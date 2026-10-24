#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations


# PBKDF2-HMAC-SHA256, 100000 rounds, passlib style: base64 with . for + and no padding.

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 100000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def _ab64(data):
  return base64.b64encode(data).decode().replace("+", ".").rstrip("=")


def _ab64_decode(text):
  return base64.b64decode(text.replace(".", "+") + "=" * (-len(text) % 4))


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, ITERATIONS)

  return "$pbkdf2-sha256$100000$%s$%s" % (_ab64(salt_bytes), _ab64(key))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$pbkdf2-sha256$100000$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 4 or len(fields[3]) != 43:
    return None

  try:
    salt = _ab64_decode(fields[3]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt), word)
