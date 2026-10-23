#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import runtime_iterations, split_hash_salt_word, iteration_override_enabled

# Salesforce sha512+sha256: 10000 rounds of sha512 over the running hex digest, the salt appended
# once the loop passes 5000, then a final sha256.

NORMAL_ITERATIONS = 10000
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cur = word

  for i in range(ITERATIONS):
    if i > 5000:
      cur += salt.encode()

    cur = hashlib.sha512(cur).hexdigest().encode()

  return "%s:%s" % (hashlib.sha256(cur).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
