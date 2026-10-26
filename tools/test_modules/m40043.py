#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import passlib_pbkdf2

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'ci_seconds': {'opt': 1, 'pure': 43, 'bridge': 2, 'edge': 144}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 43, 'edge': 141},
    },
  }


# Python passlib pbkdf2-sha256, see lib/passlib_pbkdf2.py.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  return passlib_pbkdf2.generate_hash("$pbkdf2-sha256$", "sha256", word, salt.encode("latin-1") if salt else None, iterations)


def module_verify_hash(line):
  return passlib_pbkdf2.verify_hash("$pbkdf2-sha256$", "sha256", line)
