#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string

# md5($salt1.sha1($salt2.$pass)), both salts in the line.


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 55], [0, 55]]


def module_generate_hash(word, salt, iterations=None, salt2=None):
  if salt2 is None:
    salt2 = random_hex_string(32)

  inner = hashlib.sha1(salt2.encode() + word).hexdigest().encode()

  return "%s:%s:%s" % (hashlib.md5(salt.encode() + inner).hexdigest(), salt, salt2)


def module_verify_hash(line):
  parts = line.split(b":", 3)

  if len(parts) != 4:
    return None

  _, salt1, salt2, word = parts

  return (module_generate_hash(word, salt1.decode(), None, salt2.decode()), word)
