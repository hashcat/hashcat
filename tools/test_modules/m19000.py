#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import qnx

# QNX /etc/shadow (MD5), see lib/qnx.py.


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return qnx.generate_hash("m", hashlib.md5, word, salt, iterations)


def module_verify_hash(line):
  return qnx.verify_hash("m", hashlib.md5, line)
