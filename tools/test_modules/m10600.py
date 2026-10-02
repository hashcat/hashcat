#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# PDF 1.7 Level 3 (Acrobat 9): the U entry is SHA-256 of the password and the 8 byte validation
# salt, followed by the rest of U as it was. The salt argument is the document id.

PREFIX = "$pdf$5*5*256*-1028*1*16*"


def default_rest(doc_id):
  return ("127*" + "0" * 64 + doc_id + "0" * 158 + "*127*" + "0" * 254 +
          "*32*" + "0" * 64 + "*32*" + "0" * 64)


def module_constraints():
  return [[0, 127], [32, 32], [0, 31], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, rest=None):
  doc_id = salt if salt is not None else "0" * 32

  if rest is None:
    rest = default_rest(doc_id)

  data = rest.split("*")

  u = bytes.fromhex(data[1])

  data[1] = (hashlib.sha256(word + u[32:40]).digest() + u[32:]).hex()

  return PREFIX + doc_id + "*" + "*".join(data)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) < 11 or data[:6] != ["$pdf$5", "5", "256", "-1028", "1", "16"]:
    return None

  try:
    return (module_generate_hash(word, data[6], None, "*".join(data[7:])), word)
  except (ValueError, IndexError):
    return None
