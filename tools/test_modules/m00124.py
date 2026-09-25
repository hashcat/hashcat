#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Django (SHA-1): sha1$salt$digest.


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 55], [0, 55]]


def module_generate_hash(word, salt, iterations=None):
  return "sha1$%s$%s" % (salt, hashlib.sha1(salt.encode() + word).hexdigest())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 3 or data[0] != "sha1":
    return None

  return (module_generate_hash(word, data[1]), word)
