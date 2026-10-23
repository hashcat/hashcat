#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

from lib.test_helpers import iteration_override_enabled, runtime_iterations

# NetIQ SSPR (MD5): 100000 rounds, no salt, see lib/sspr.py.

NORMAL_ITERATIONS = 100000
ITERATIONS = NORMAL_ITERATIONS

if iteration_override_enabled():
  ITERATIONS = runtime_iterations(NORMAL_ITERATIONS, initial=1)


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(0, hashlib.md5, NORMAL_ITERATIONS, word, "NONE", effective_iterations=ITERATIONS)


def module_verify_hash(line):
  parsed = sspr.parse(0, NORMAL_ITERATIONS, line)

  if parsed is None or parsed[0] != "NONE":
    return None

  return (module_generate_hash(parsed[1], None), parsed[1])
