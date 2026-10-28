#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [1, 15],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 1000}, 'ci_seconds': {'opt': 1, 'pure': 46, 'bridge': 2, 'edge': 268}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 33, 'edge': 248},
    },
  }


# Web2py pbkdf2-sha512: pbkdf2(iterations,20,sha512)$salt$key, the key as long as the line says.

LINE = re.compile(r"^pbkdf2\((\d+),(\d+),sha512\)\$([^$]*)\$([0-9a-fA-F]*)$")


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, out_len=20):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

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
