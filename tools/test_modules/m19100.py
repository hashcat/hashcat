#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import qnx

from lib.test_helpers import test_iteration_parameters

# QNX /etc/shadow (SHA256), see lib/qnx.py.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(19100)


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return qnx.generate_hash("s", hashlib.sha256, word, salt, iterations)


def module_verify_hash(line):
  return qnx.verify_hash("s", hashlib.sha256, line)
