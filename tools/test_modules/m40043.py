#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import passlib_pbkdf2

from lib.test_helpers import test_iteration_parameters

# Python passlib pbkdf2-sha256, see lib/passlib_pbkdf2.py.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40043)


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return passlib_pbkdf2.generate_hash("$pbkdf2-sha256$", "sha256", word, salt.encode("latin-1") if salt else None, iterations)


def module_verify_hash(line):
  return passlib_pbkdf2.verify_hash("$pbkdf2-sha256$", "sha256", line)
