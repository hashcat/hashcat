#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import aix

from lib.test_helpers import test_iteration_parameters

# AIX {ssha1}: PBKDF2-HMAC-SHA1, see lib/aix.py.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40017)

NORMAL_ITERATIONS = 64
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  return aix.generate_hash("ssha1", "sha1", word, salt, iterations)


def module_verify_hash(line):
  return aix.verify_hash("ssha1", "sha1", line)
