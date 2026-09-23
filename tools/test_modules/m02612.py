#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# PHPS: $PHPS$hex(salt)$md5(md5(pass).salt).


def module_constraints():
  return [[0, 256], [0, 223], [0, 55], [1, 23], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  digest = hashlib.md5(hashlib.md5(word).hexdigest().encode() + salt_bytes).hexdigest()

  return "$PHPS$%s$%s" % (salt_bytes.hex(), digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 4 or data[1] != "PHPS":
    return None

  try:
    salt = bytes.fromhex(data[2]).decode("latin-1")
  except ValueError:
    return None

  return (module_generate_hash(word, salt), word)
