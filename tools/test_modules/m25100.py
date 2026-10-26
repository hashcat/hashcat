#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import snmpv3

# SNMPv3 HMAC-MD5-96, see lib/snmpv3.py.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [8, 256],
        'salt_length': [24, 3000],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return snmpv3.generate_hash(1, hashlib.md5, word, salt)


def module_verify_hash(line):
  return snmpv3.verify_hash(1, hashlib.md5, line)
