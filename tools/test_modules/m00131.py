#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# MSSQL (2000): the upper cased password widened to UTF-16LE byte by byte, then the 4 byte salt.
# bytes.upper () folds ASCII only, which is what perl's uc () does to a byte string.


def module_constraints():
  return [[0, 256], [8, 8], [0, 27], [8, 8], [8, 27]]


def module_generate_hash(word, salt, iterations=None):
  wide = word.upper().decode("latin-1").encode("utf-16-le")

  digest = hashlib.sha1(wide + bytes.fromhex(salt)).hexdigest()

  return "0x0100%s%s%s" % (salt, "0" * 40, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    return (module_generate_hash(word, hash_in[6:14]), word)
  except ValueError:
    return None
