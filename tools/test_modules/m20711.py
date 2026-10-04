#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# AuthMe sha256: $SHA$salt$sha256(sha256($pass).$salt).


def module_constraints():
  return [[0, 256], [16, 16], [0, 55], [16, 16], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha256(hashlib.sha256(word).hexdigest().encode() + salt.encode()).hexdigest()

  return "$SHA$%s$%s" % (salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) < 4 or data[1] != "SHA" or len(data[2]) != 16:
    return None

  return (module_generate_hash(word, data[2]), word)
