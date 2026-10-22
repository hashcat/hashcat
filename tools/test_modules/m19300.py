#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_numeric_string

# sha1($salt1.$pass.$salt2), both salts in the line.


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, salt2=None):
  salt2 = salt2 or random_numeric_string(256)

  return "%s:%s:%s" % (hashlib.sha1(salt.encode() + word + salt2.encode()).hexdigest(), salt, salt2)


def module_verify_hash(line):
  parts = line.split(b":", 3)

  if len(parts) != 4:
    return None

  _, salt1, salt2, word = parts

  return (module_generate_hash(word, salt1.decode(), None, salt2.decode()), word)
