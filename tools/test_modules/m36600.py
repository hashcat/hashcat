#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pbkdf2_b64
from lib.test_helpers import kernel_charset, utf16le, test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (2, 16)},
  }


# PBKDF2-HMAC-SHA512 over a UTF-16LE password: sha512utf16le:iterations:base64(salt):base64(key).
# The optimized kernels widen each password byte instead of decoding UTF-8, so the oracle picks its
# charset from IS_OPTIMIZED the way the runner sets it, then encodes UTF-16LE, matching module_01000.

CHARSET = kernel_charset()


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(36600)

NORMAL_ITERATIONS = 1000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, out_len=64):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  return pbkdf2_b64.generate_hash("sha512utf16le", "sha512", utf16le(word, CHARSET), salt, iterations, out_len)


def module_verify_hash(line):
  parsed = pbkdf2_b64.parse("sha512utf16le", line)

  if parsed is None:
    return None

  salt, iterations, out_len, word = parsed

  return (module_generate_hash(word, salt, iterations, out_len), word)
