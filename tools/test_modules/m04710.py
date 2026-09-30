#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 64], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  digest = hashlib.sha1(hashlib.md5(word).hexdigest().encode() + salt_bytes).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
