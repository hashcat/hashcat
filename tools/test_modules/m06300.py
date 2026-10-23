#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md5crypt
from lib.test_helpers import split_hash_word, test_iteration_parameters

# AIX {smd5}: md5crypt with an empty magic and an optional encoded round count.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(6300)

NORMAL_ITERATIONS = 1000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [0, 8], [0, 15], [0, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  return "{smd5}" + md5crypt.md5_crypt(b"", iterations, word, salt.encode("latin-1"))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  salt = hash_in[hash_in.find("}") + 1:hash_in.rfind("$")]

  iterations = 1000

  if salt.startswith("rounds="):
    rounds, salt = salt.split("$", 1)
    iterations = int(rounds[len("rounds="):])

  return (module_generate_hash(word, salt, iterations), word)
