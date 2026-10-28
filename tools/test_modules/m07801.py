#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import sap

# SAP CODVN F/G (PASSCODE) mangled, the second half zeroed, see lib/sap.py.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': None,
      'optimized': {
        'password_length': [0, 40],
        'salt_length': [1, 12],
      },
      'combined_length': [0, 55],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  salt = salt.upper()

  return "%s$%.20s%020X" % (salt, sap.passcode(word, salt.encode()), 0)


def module_verify_hash(line):
  parts = sap.split_line(line)

  if parts is None:
    return None

  salt, word = parts

  return (module_generate_hash(word, salt.decode()), word)
