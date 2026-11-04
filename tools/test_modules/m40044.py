#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import passlib_pbkdf2

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
    'reduced': {'parameters': {'iterations': 2}, 'ci_seconds': {'opt': 1, 'pure': 31, 'edge': 70}},
    'normal': {'ci_seconds': {'bridge': 2, 'pure': 54, 'opt': 1, 'edge': 113}},
  }


# Python passlib pbkdf2-sha1, see lib/passlib_pbkdf2.py.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  return passlib_pbkdf2.generate_hash("$pbkdf2$", "sha1", word, salt.encode("latin-1") if salt else None, iterations)


def module_verify_hash(line):
  return passlib_pbkdf2.verify_hash("$pbkdf2$", "sha1", line)
