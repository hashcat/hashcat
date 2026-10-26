#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import hmac
import re

from lib.test_helpers import random_number, random_string, split_hash_word, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 10000}, 'ci_seconds': {'opt': 1, 'pure': 29, 'bridge': 2, 'edge': 122}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 32, 'edge': 92},
    },
  }


# MongoDB ServerKey SCRAM-SHA-1: HMAC-SHA1 of "Server Key" keyed with PBKDF2-HMAC-SHA1
# of md5(user:mongo:pass) in hex, the user name drawn at random.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, user=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  if user is None:
    user = random_string(random_number(0, 57)).encode()

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  key = hashlib.pbkdf2_hmac("sha1", hashlib.md5(user + b":mongo:" + word).hexdigest().encode(), salt_bytes, iterations, 20)

  digest = hmac.new(key, b"Server Key", hashlib.sha1).digest()

  return "$mongodb-scram$*0*%s*%d*%s*%s" % (base64.b64encode(user).decode(), iterations,
                                             base64.b64encode(salt_bytes).decode(), base64.b64encode(digest).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$mongodb-scram$*0"):
    return None

  data = hash_in.split("*")

  if len(data) < 5:
    return None

  _, _, user, iterations, salt = data[:5]

  if not re.fullmatch(r"[A-Za-z0-9+/=]{0,76}", user) or not re.fullmatch(r"[1-9][0-9]{0,7}", iterations):
    return None

  if not re.fullmatch(r"[A-Za-z0-9+/=]{24}", salt):
    return None

  try:
    user = base64.b64decode(user)
    salt = base64.b64decode(salt)
  except binascii.Error:
    return None

  if len(user) > 57:
    return None

  return (module_generate_hash(word, salt, iterations, user), word)
