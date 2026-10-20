#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# MySQL caching_sha2_password fast authentication, Generate_scramble::scramble () in MySQL's
# sql/auth/sha2_password_common.cc: sha256(pass) XOR sha256(sha256(sha256(pass)) . nonce), with the
# 20 byte nonce of the server greeting as the salt, in hex.


def module_constraints():
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  stage1 = hashlib.sha256(word).digest()
  stage2 = hashlib.sha256(stage1).digest()

  scramble_stage1 = hashlib.sha256(stage2 + bytes.fromhex(salt)).digest()

  scramble = bytes(a ^ b for a, b in zip(stage1, scramble_stage1))

  return "$mysqlsha2$%s*%s" % (salt, scramble.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 3 or data[1] != "mysqlsha2":
    return None

  fields = data[2].split("*")

  if len(fields) != 2:
    return None

  try:
    return (module_generate_hash(word, fields[0]), word)
  except ValueError:
    return None
