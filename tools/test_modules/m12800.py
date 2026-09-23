#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import MD4

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# MS-AzureSync PBKDF2-HMAC-SHA256: PBKDF2 over the NT hash written in upper case hex and widened to
# UTF-16LE. The two kernel families convert the password to UTF-16 differently, see
# kernel_charset (); MD4 is pycryptodome's, because hashlib often has none.

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [20, 20], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 100 if iterations is None else int(iterations)

  nt = MD4.new(utf16le(word, CHARSET)).hexdigest()

  key = hashlib.pbkdf2_hmac("sha256", nt.upper().encode("utf-16-le"), bytes.fromhex(salt), iterations, 32)

  return "v1;PPH1_MD4,%s,%d,%s" % (salt, iterations, key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split(",")

  if len(data) != 4 or data[0] != "v1;PPH1_MD4":
    return None

  try:
    return (module_generate_hash(word, data[1], data[2]), word)
  except ValueError:
    return None
