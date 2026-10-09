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
  # The DES key is the first 8 bytes of the candidate, the same bytes the kernel keys on. Slicing to
  # word[0:8] (as mode 14100 does for its three keys) keeps this valid when the candidate carries a
  # multibyte character and so runs past 8 bytes, rather than handing DES a key of the wrong size.
  ct = DES.new(word[0:8], DES.MODE_ECB).encrypt(bytes.fromhex(salt))

  return "%s:%s" % (ct.hex(), salt)


def module_verify_hash(line):
  # The hash is "ct:salt", both halves separated by a colon, so the recovered line is
  # "ct:salt:password" and the hash has to be split off as two fields, not at the first colon (which
  # would hand the salt to the password). Mode 14100 splits its hash the same way.

  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
