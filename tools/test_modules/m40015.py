#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import aix

# AIX {ssha256}: PBKDF2-HMAC-SHA256, see lib/aix.py.


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 64 if iterations is None else 1 << int(iterations)

  return aix.generate_hash("ssha256", "sha256", word, salt, iterations)


def module_verify_hash(line):
  return aix.verify_hash("ssha256", "sha256", line)
