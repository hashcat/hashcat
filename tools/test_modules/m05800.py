#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import runtime_iterations, split_hash_salt_word


# Samsung Android password/PIN: 1024 rounds of SHA-1, each over the last digest, the round number in
# decimal, the password and the salt.

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [1, 16],
      },
      'optimized': {
        'password_length': [0, 13],
        'salt_length': [16, 16],
      },
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 1024}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt, iterations=None):
  tail = word + salt.encode()

  digest = hashlib.sha1(b"0" + tail).digest()

  for i in range(1, ITERATIONS):
    digest = hashlib.sha1(digest + str(i).encode() + tail).digest()

  return "%s:%s" % (digest.hex(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
