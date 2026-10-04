#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

# NetIQ SSPR (Salted SHA512): 1000 rounds, a 16 character salt, see lib/sspr.py.


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(4, hashlib.sha512, 1000, word, salt)


def module_verify_hash(line):
  parsed = sspr.parse(4, 1000, line)

  if parsed is None or len(parsed[0]) != 16:
    return None

  return (module_generate_hash(parsed[1], parsed[0]), parsed[1])
