#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import bestcrypt

# BestCrypt container (.jbc) key slots whose key generator runs SHA-512. One pass of the
# derivation covers both cipher modes here, so the cipher stays a field of the hash and generation
# draws one of the two.

MODES = (bestcrypt.MODE_CBC, bestcrypt.MODE_XTS)


def module_constraints():
  return [[0, 63], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, source=None):
  return bestcrypt.generate_hash(bestcrypt.SHA512, word, salt, iterations, source, MODES)


def module_verify_hash(line):
  return bestcrypt.verify_hash(bestcrypt.SHA512, line, MODES)
