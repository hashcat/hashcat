#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

# ShangMi 3 (SM3), raw unsalted digest. Nothing in the standard library implements it directly,
# but OpenSSL does, so hashlib reaches it by name.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return hashlib.new("sm3", word).hexdigest()


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  word = line[idx + 1:]

  return (module_generate_hash(word, None), word)
