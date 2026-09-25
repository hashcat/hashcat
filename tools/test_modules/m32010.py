#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import sspr

# NetIQ SSPR (SHA1): 100000 rounds, no salt, see lib/sspr.py.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(1, hashlib.sha1, 100000, word, "NONE")


def module_verify_hash(line):
  parsed = sspr.parse(1, 100000, line)

  if parsed is None or parsed[0] != "NONE":
    return None

  return (module_generate_hash(parsed[1], None), parsed[1])
