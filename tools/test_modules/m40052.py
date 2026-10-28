#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_word, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 4096}, 'ci_seconds': {'opt': 1, 'pure': 27, 'bridge': 2, 'edge': 153}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 31, 'edge': 114},
    },
  }


# XMPP SCRAM PBKDF2-SHA1: SHA-1 of HMAC-SHA1("Client Key") keyed with PBKDF2-HMAC-SHA1 of the
# password.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bytes, iterations, 20)

  digest = hashlib.sha1(hmac.new(key, b"Client Key", hashlib.sha1).digest()).hexdigest()

  return "$xmpp-scram$0$%d$%d$%s$%s" % (iterations, len(salt_bytes), salt_bytes.hex(), digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) < 7 or data[1] != "xmpp-scram" or data[2] != "0":
    return None

  try:
    salt = bytes.fromhex(data[5])
  except ValueError:
    return None

  if data[4] != str(len(salt)):
    return None

  return (module_generate_hash(word, salt, data[3]), word)
