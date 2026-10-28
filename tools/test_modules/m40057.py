#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

# NetIQ SSPR (MD5): 100000 rounds, no salt, see lib/sspr.py.


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
  }


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(0, hashlib.md5, 100000, word, "NONE")


def module_verify_hash(line):
  parsed = sspr.parse(0, 100000, line)

  if parsed is None or parsed[0] != "NONE":
    return None

  return (module_generate_hash(parsed[1], None), parsed[1])
