#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import snmpv3

# SNMPv3 HMAC-SHA224-128, see lib/snmpv3.py.


def module_constraints():
  return [[8, 256], [32, 3000], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return snmpv3.generate_hash(3, hashlib.sha224, word, salt, None, None, 32)


def module_verify_hash(line):
  return snmpv3.verify_hash(3, hashlib.sha224, line, 32)
