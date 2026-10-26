#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pkzip

# PKZIP ZipCrypto, the container shape for mode 17225, see lib/pkzip.py.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 64],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return pkzip.generate_hash(17225, word)


def module_verify_hash(line):
  return pkzip.verify_hash(line)
