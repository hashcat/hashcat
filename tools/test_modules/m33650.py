#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import ripemd320
from lib.test_helpers import split_hash_salt_word

# HMAC-RIPEMD320 keyed with the password (perl hmac (data = salt, key = password)).


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 55], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return "%s:%s" % (ripemd320.hmac_ripemd320_hex(word, salt.encode()), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
