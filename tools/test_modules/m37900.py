#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import bestcrypt

# BestCrypt container (.jbc) key slots whose key generator runs SHA-256 with AES-CBC. The cipher is
# part of the mode here rather than a field of the hash, because the XTS key takes a second pass
# of the derivation and the CBC key does not, and the count of passes has to be the same for
# every salt of one mode.

MODES = (bestcrypt.MODE_CBC,)


def module_constraints():
  return [[0, 63], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, source=None):
  return bestcrypt.generate_hash(bestcrypt.SHA256, word, salt, iterations, source, MODES)


def module_verify_hash(line):
  return bestcrypt.verify_hash(bestcrypt.SHA256, line, MODES)
