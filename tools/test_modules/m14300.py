#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.test_helpers import split_hash_salt_word

# 2 key 3DES (EDE) of the salt, one block, encrypt then decrypt then encrypt. The 16 byte password
# is the key material split into halves, and the third key is the first one again.


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [16, 16],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  cipher1 = DES.new(word[0:8], DES.MODE_ECB)
  cipher2 = DES.new(word[8:16], DES.MODE_ECB)

  pt1 = bytes.fromhex(salt)

  ct1 = cipher1.encrypt(pt1)
  ct2 = cipher2.decrypt(ct1)
  ct3 = cipher1.encrypt(ct2)

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
