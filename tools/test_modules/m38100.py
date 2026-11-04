#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import ike
from lib.test_helpers import random_bytes

# IKE-PSK SHA256, see lib/ike.py.


def module_test_properties():
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
  if not salt:
    fields = ike.random_salt().split(":")

    # Group 14 public values are 256 bytes each.
    fields[0] = random_bytes(256).hex()
    fields[1] = random_bytes(256).hex()

    salt = ":".join(fields)

  return ike.generate_hash(hashlib.sha256, word, salt)


def module_verify_hash(line):
  return ike.verify_hash(hashlib.sha256, line)
