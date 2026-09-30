#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# PeopleSoft: base64 of SHA-1 over the password widened to UTF-16LE byte by byte.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  wide = word.decode("latin-1").encode("utf-16-le")

  return base64.b64encode(hashlib.sha1(wide).digest()).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
