#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_salt_word

# AES-128-ECB with the password as key (zero padded), encrypting the 16 byte salt.


def module_constraints():
  return [[0, 16], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  key = (word + b"\x00" * 16)[:16]

  ct = AES.new(key, AES.MODE_ECB).encrypt(bytes.fromhex(salt))

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
