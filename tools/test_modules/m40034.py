#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pbkdf2_b64

from lib.test_helpers import test_iteration_parameters

# PBKDF2-HMAC-SHA512: sha512:iterations:base64(salt):base64(key), see lib/pbkdf2_b64.py.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40034)

NORMAL_ITERATIONS = 1000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, out_len=16):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  return pbkdf2_b64.generate_hash("sha512", "sha512", word, salt, iterations, out_len)


def module_verify_hash(line):
  parsed = pbkdf2_b64.parse("sha512", line)

  if parsed is None:
    return None

  salt, iterations, out_len, word = parsed

  return (module_generate_hash(word, salt, iterations, out_len), word)
