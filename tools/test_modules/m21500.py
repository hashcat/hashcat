#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word, runtime_iterations


# SolarWinds Orion: SHA-512 of a 1024 byte PBKDF2-HMAC-SHA1 key, salted with the first 8 characters
# of the salt, padded out with a fixed string when it is shorter.

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
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 1000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None):
  custom = (salt[:8] + "1244352345234")[:8]

  key = hashlib.pbkdf2_hmac("sha1", word, custom.encode("latin-1"), ITERATIONS, 1024)

  return "$solarwinds$0$%s$%s" % (salt, base64.b64encode(hashlib.sha512(key).digest()).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 5 or data[1] != "solarwinds" or data[2] != "0" or len(data[3]) > 256 or len(data[4]) != 88:
    return None

  return (module_generate_hash(word, data[3]), word)
