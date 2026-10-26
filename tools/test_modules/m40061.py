#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

# NetIQ SSPR (Salted SHA256): 1000 rounds, a 16 character salt, see lib/sspr.py.


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
  }


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(3, hashlib.sha256, 1000, word, salt)


def module_verify_hash(line):
  parsed = sspr.parse(3, 1000, line)

  if parsed is None or len(parsed[0]) != 16:
    return None

  return (module_generate_hash(parsed[1], parsed[0]), parsed[1])
