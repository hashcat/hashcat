#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
from functools import partial

from lib.test_helpers import kernel_charset, split_hash_word, utf16le, iteration_override_enabled, runtime_iteration_limit


# MS Office 2016 SheetProtection: SHA-512 of the salt and the UTF-16LE password, then of the digest
# and the round number as 4 little endian bytes, iterations times. The two kernel families convert
# the password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 64],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 100000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']


COMPUTE_ITERATIONS = int

if iteration_override_enabled():
  COMPUTE_ITERATIONS = partial(min, runtime_iteration_limit())


def module_generate_hash(word, salt, iterations=None):
  iterations = ITERATION_DEFAULTS['iterations'] if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  tmp = hashlib.sha512(salt_bytes + utf16le(word, CHARSET)).digest()

  for i in range(COMPUTE_ITERATIONS(iterations)):
    tmp = hashlib.sha512(tmp + i.to_bytes(4, "little")).digest()

  return "$office$2016$0$%d$%s$%s" % (iterations, base64.b64encode(salt_bytes).decode(), base64.b64encode(tmp).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 7 or data[1:4] != ["office", "2016", "0"] or len(data[5]) != 24 or len(data[6]) != 88:
    return None

  return (module_generate_hash(word, base64.b64decode(data[5]).decode("latin-1"), data[4]), word)
