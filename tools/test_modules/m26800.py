#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import snmpv3

# SNMPv3 HMAC-SHA256-192, see lib/snmpv3.py.


def module_constraints():
  return [[8, 256], [48, 3000], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return snmpv3.generate_hash(4, hashlib.sha256, word, salt, None, None, 48)


def module_verify_hash(line):
  return snmpv3.verify_hash(4, hashlib.sha256, line, 48)
