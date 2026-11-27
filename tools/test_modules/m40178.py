#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import configmgr

ALG_ID = 0x6610
KEYLEN = 32


def module_test_properties():
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
  return configmgr.generate(word, ALG_ID, KEYLEN)


def module_verify_hash(line):
  return configmgr.verify(line, ALG_ID, KEYLEN)
