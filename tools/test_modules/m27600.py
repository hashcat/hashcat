#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import virtualbox

from lib.test_helpers import test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (2, 16), 'iterations2': (2, 16)},
  }


# VirtualBox, PBKDF2-HMAC-SHA256 and AES-256-XTS, see lib/virtualbox.py.

KEY_LEN = 64

ITER1 = 160000


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(27600)


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iterations2=None):
  return virtualbox.generate_hash(KEY_LEN, ITER1, word, salt, iterations, iter2=iterations2)


def module_verify_hash(line):
  return virtualbox.verify_hash(KEY_LEN, ITER1, line)
