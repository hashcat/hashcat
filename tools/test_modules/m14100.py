#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.test_helpers import split_hash_salt_word

# 3DES (EDE, three independent 8 byte keys) of the salt, one block, encrypt then decrypt then
# encrypt. The 24 byte password is the key material split into thirds.


def module_constraints():
  return [[24, 24], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cipher1 = DES.new(word[0:8], DES.MODE_ECB)
  cipher2 = DES.new(word[8:16], DES.MODE_ECB)
  cipher3 = DES.new(word[16:24], DES.MODE_ECB)

  pt1 = bytes.fromhex(salt)

  ct1 = cipher1.encrypt(pt1)
  ct2 = cipher2.decrypt(ct1)
  ct3 = cipher3.encrypt(ct2)

  return "%s:%s" % (ct3.hex(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
