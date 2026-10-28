#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import ike

# IKE-PSK MD5, see lib/ike.py.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return ike.generate_hash(hashlib.md5, word, salt)


def module_verify_hash(line):
  return ike.verify_hash(hashlib.md5, line)
