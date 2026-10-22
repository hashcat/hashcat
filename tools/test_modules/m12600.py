#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# ColdFusion 10+: sha256($salt.strtoupper(sha1($pass))).


def module_constraints():
  return [[0, 256], [64, 64], [0, 55], [64, 64], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  inner = hashlib.sha1(word).hexdigest().upper().encode()

  return "%s:%s" % (hashlib.sha256(salt.encode() + inner).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
