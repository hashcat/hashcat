#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# The two kernel families convert the password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return hashlib.sha1(utf16le(word, CHARSET)).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
