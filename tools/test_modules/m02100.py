#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import MD4

from lib.test_helpers import kernel_charset, split_hash_word, utf16le, test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'iterations': (2, 16)},
  }


# Domain Cached Credentials 2: PBKDF2-HMAC-SHA1 over DCC1, salted with the lower cased user name in
# UTF-16LE. The two kernel families convert the password to UTF-16 differently, see
# kernel_charset (); MD4 is pycryptodome's, because hashlib often has none.

CHARSET = kernel_charset()


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(2100)

NORMAL_ITERATIONS = 10240
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  salt_bin = salt.lower().encode("utf-16-le")

  dcc1 = MD4.new(MD4.new(utf16le(word, CHARSET)).digest() + salt_bin).digest()

  digest = hashlib.pbkdf2_hmac("sha1", dcc1, salt_bin, iterations, 16).hex()

  return "$DCC2$%d#%s#%s" % (iterations, salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$DCC2$"):
    return None

  data = hash_in[6:].split("#")

  if len(data) != 3:
    return None

  return (module_generate_hash(word, data[1], data[0]), word)
