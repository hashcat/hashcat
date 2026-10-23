#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import test_iteration_parameters

# Oracle Transportation Management (SHA256): SHA-256 of the salt and the password, then of the
# digest, iterations times in all.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40045)

NORMAL_ITERATIONS = 1000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [0, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  digest = hashlib.sha256(salt.encode() + word).digest()

  for _ in range(1, iterations):
    digest = hashlib.sha256(digest).digest()

  return "otm_sha256:%d:%s:%s" % (iterations, salt, base64.b64encode(digest).decode())


def module_verify_hash(line):
  parts = line.split(b":", 4)

  if len(parts) != 5 or not parts[1].isdigit():
    return None

  _, iterations, salt, _, word = parts

  return (module_generate_hash(word, salt.decode(), iterations), word)
