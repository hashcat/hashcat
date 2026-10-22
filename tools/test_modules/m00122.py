#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# macOS v10.4 to v10.6: 4 byte salt in hex, then the digest.


def module_constraints():
  return [[0, 256], [8, 8], [0, 55], [8, 8], [8, 55]]


def module_generate_hash(word, salt, iterations=None):
  return salt + hashlib.sha1(bytes.fromhex(salt) + word).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    return (module_generate_hash(word, hash_in[:8]), word)
  except ValueError:
    return None
