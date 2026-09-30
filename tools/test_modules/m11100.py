#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# PostgreSQL CRAM (MD5): md5(md5(pass.user).salt), the 4 byte salt in hex.


def module_constraints():
  return [[0, 256], [8, 8], [0, 55], [8, 8], [0, 55]]


def module_generate_hash(word, salt, iterations=None, user="postgres"):
  inner = hashlib.md5(word + user.encode()).hexdigest().encode()

  return "$postgres$%s*%s*%s" % (user, salt, hashlib.md5(inner + bytes.fromhex(salt)).hexdigest())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) < 3 or data[1] != "postgres":
    return None

  fields = data[2].split("*")

  if len(fields) < 2:
    return None

  try:
    return (module_generate_hash(word, fields[1], None, fields[0]), word)
  except ValueError:
    return None
