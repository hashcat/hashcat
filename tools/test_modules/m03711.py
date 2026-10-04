#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# MediaWiki B type: $B$salt$md5(salt-md5(pass)).


def module_constraints():
  return [[0, 256], [0, 221], [0, 55], [0, 22], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  digest = hashlib.md5(salt_bytes + b"-" + hashlib.md5(word).hexdigest().encode()).hexdigest()

  return "$B$%s$%s" % (salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 4:
    return None

  return (module_generate_hash(word, data[2]), word)
