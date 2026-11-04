#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import bestcrypt

# BestCrypt container (.jbc) key slots whose key generator runs Whirlpool-512. One pass of the
# derivation covers both cipher modes here, so the cipher stays a field of the hash and generation
# draws one of the two.

MODES = (bestcrypt.MODE_CBC, bestcrypt.MODE_XTS)


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 63],
        'salt_length': [128, 128],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None, source=None):
  return bestcrypt.generate_hash(bestcrypt.WHIRLPOOL, word, salt, iterations, source, MODES)


def module_verify_hash(line):
  return bestcrypt.verify_hash(bestcrypt.WHIRLPOOL, line, MODES)
