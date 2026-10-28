#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import virtualbox

# VirtualBox, PBKDF2-HMAC-SHA256 and AES-256-XTS, see lib/virtualbox.py.

KEY_LEN = 64

ITER1 = 160000


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [64, 64],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return virtualbox.generate_hash(KEY_LEN, ITER1, word, salt, iterations)


def module_verify_hash(line):
  return virtualbox.verify_hash(KEY_LEN, ITER1, line)
