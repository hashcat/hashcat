#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib import sspr

# NetIQ SSPR (Salted SHA1): 100000 rounds, a 24 byte salt in base64, see lib/sspr.py.


def module_constraints():
  return [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return sspr.generate_hash(2, hashlib.sha1, 100000, word, base64.b64encode(salt.encode("latin-1")).decode())


def module_verify_hash(line):
  parsed = sspr.parse(2, 100000, line)

  if parsed is None or len(parsed[0]) != 32:
    return None

  try:
    salt = base64.b64decode(parsed[0])
  except binascii.Error:
    return None

  if len(salt) != 24:
    return None

  return (module_generate_hash(parsed[1], salt.decode("latin-1")), parsed[1])
