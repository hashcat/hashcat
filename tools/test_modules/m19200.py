#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import qnx

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'ci_seconds': {'opt': 1, 'pure': 42, 'bridge': 2, 'edge': 141}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 46, 'edge': 147},
    },
  }


# QNX /etc/shadow (SHA512), see lib/qnx.py.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  return qnx.generate_hash("S", hashlib.sha512, word, salt, iterations)


def module_verify_hash(line):
  return qnx.verify_hash("S", hashlib.sha512, line)
