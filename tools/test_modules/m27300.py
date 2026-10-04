#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import snmpv3

# SNMPv3 HMAC-SHA512-384, see lib/snmpv3.py. Unlike 26900 the line carries the padded engine id.


def module_constraints():
  return [[8, 256], [96, 3000], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return snmpv3.generate_hash(6, hashlib.sha512, word, salt, None, None, 96, 34, True)


def module_verify_hash(line):
  return snmpv3.verify_hash(6, hashlib.sha512, line, 96, 34, True)
