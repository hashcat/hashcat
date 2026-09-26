#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pkzip

# PKZIP checksum only, which needs at least three deflated files.


def module_constraints():
  return [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return pkzip.generate_hash(pkzip.deflate_many(3, 8), word)


def module_verify_hash(line):
  return pkzip.verify_hash(line)
