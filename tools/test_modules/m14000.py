#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.test_helpers import split_hash_salt_word

# DES (PT = $salt, key = $pass): one block of DES-ECB, the 8 byte password as key, the 8 byte salt
# (16 hex) as plaintext.


def module_constraints():
  return [[8, 8], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  ct = DES.new(word, DES.MODE_ECB).encrypt(bytes.fromhex(salt))

  return "%s:%s" % (ct.hex(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
