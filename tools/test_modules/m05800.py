#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import runtime_iterations, split_hash_salt_word, iteration_override_enabled


def module_reduced_iteration_constraints():
  return {
    'runtime_limits': {'iterations': (1, 16)},
  }


# Samsung Android password/PIN: 1024 rounds of SHA-1, each over the last digest, the round number in
# decimal, the password and the salt.

NORMAL_ITERATIONS = 1024
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [1, 16], [0, 13], [16, 16], [-1, -1]]


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
