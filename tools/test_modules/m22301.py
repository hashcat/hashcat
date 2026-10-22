#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Telegram Mobile App Passcode (SHA256): sha256 of the 16 byte salt, the passcode and the salt again.


def module_constraints():
  return [[0, 256], [32, 32], [0, 55], [32, 32], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  return "$telegram$0*%s*%s" % (hashlib.sha256(salt_bin + word + salt_bin).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 3 or data[0] != "$telegram$0" or len(data[1]) != 64 or len(data[2]) != 32:
    return None

  try:
    return (module_generate_hash(word, data[2]), word)
  except ValueError:
    return None
