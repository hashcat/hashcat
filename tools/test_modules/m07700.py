#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import sap

# SAP CODVN B (BCODE), see lib/sap.py.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 8], [1, 12], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  salt = salt.upper()

  a, b = sap.bcode(word, salt.encode())

  return "%s$%08X%08X" % (salt, a, b)


def module_verify_hash(line):
  parts = sap.split_line(line)

  if parts is None:
    return None

  salt, word = parts

  return (module_generate_hash(word, salt.decode()), word)
