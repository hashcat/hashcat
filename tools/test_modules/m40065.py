#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations, iteration_override_enabled


def module_reduced_iteration_constraints():
  return {
    'runtime_limits': {'iterations': (1, 16)},
  }


# PBKDF2-HMAC-SHA256, 100000 rounds, passlib style: base64 with . for + and no padding.

NORMAL_ITERATIONS = 100000
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def _ab64(data):
  return base64.b64encode(data).decode().replace("+", ".").rstrip("=")


def _ab64_decode(text):
  return base64.b64decode(text.replace(".", "+") + "=" * (-len(text) % 4))


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


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
