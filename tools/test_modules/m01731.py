#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# MSSQL (2012, 2014): the password widened to UTF-16LE byte by byte, then the 4 byte salt.


def module_constraints():
  return [[0, 256], [8, 8], [0, 27], [8, 8], [8, 27]]


def module_generate_hash(word, salt, iterations=None):
  wide = word.decode("latin-1").encode("utf-16-le")

  return "0x0200%s%s" % (salt, hashlib.sha512(wide + bytes.fromhex(salt)).hexdigest())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    return (module_generate_hash(word, hash_in[6:14]), word)
  except ValueError:
    return None
