#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import snmpv3

# SNMPv3 HMAC-MD5-96, see lib/snmpv3.py.


def module_constraints():
  return [[8, 256], [24, 3000], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return snmpv3.generate_hash(1, hashlib.md5, word, salt)


def module_verify_hash(line):
  return snmpv3.verify_hash(1, hashlib.md5, line)
