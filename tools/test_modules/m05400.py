#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import ike

# IKE-PSK SHA1, see lib/ike.py.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return ike.generate_hash(hashlib.sha1, word, salt)


def module_verify_hash(line):
  return ike.verify_hash(hashlib.sha1, line)
