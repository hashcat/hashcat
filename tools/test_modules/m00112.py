#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# Oracle 11g+: the salt is 10 bytes, written as 20 hex characters.


def module_constraints():
  return [[0, 30], [20, 20], [0, 30], [20, 20], [20, 55]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha1(word + bytes.fromhex(salt)).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
