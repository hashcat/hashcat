#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from lib.test_helpers import test_iteration_parameters

# Web2py pbkdf2-sha512: pbkdf2(iterations,20,sha512)$salt$key, the key as long as the line says.

LINE = re.compile(r"^pbkdf2\((\d+),(\d+),sha512\)\$([^$]*)\$([0-9a-fA-F]*)$")


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40050)

NORMAL_ITERATIONS = 1000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, out_len=20):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  key = hashlib.pbkdf2_hmac("sha512", word, salt.encode("latin-1"), iterations, out_len)

  return "pbkdf2(%d,20,sha512)$%s$%s" % (iterations, salt, key.hex())


def module_verify_hash(line):
  # the password is after the last colon, so it cannot hold one

  idx = line.rfind(b":")

  if idx < 0:
    return None

  m = LINE.match(line[:idx].decode(errors="replace"))

  if m is None:
    return None

  word = line[idx + 1:]

  return (module_generate_hash(word, m.group(3), m.group(1), len(m.group(4)) // 2), word)
