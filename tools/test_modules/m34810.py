#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# BLAKE2b-256 of pass.salt.


def module_constraints():
  return [[0, 127], [0, 127], [0, 55], [0, 55], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  return "$BLAKE2$%s:%s" % (hashlib.blake2b(word + salt.encode(), digest_size=32).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
