#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import diskcryptor

# DiskCryptor with a 512 bit key: one cipher, so two 256 bit keys, one for the data and one for
# the tweak.

CASCADES = (
  (("aes",     0, 1),),
  (("twofish", 0, 1),),
  (("serpent", 0, 1),),
)

KEY_COUNT = 2


def module_constraints():
  return [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, data=None):
  return diskcryptor.generate_hash(CASCADES, KEY_COUNT, word, salt, data)


def module_verify_hash(line):
  return diskcryptor.verify_hash(CASCADES, KEY_COUNT, line)
