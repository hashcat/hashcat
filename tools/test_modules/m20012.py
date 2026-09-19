#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import diskcryptor

# DiskCryptor with a 1024 bit key: up to two ciphers, so four 256 bit keys. A cascade takes its
# data keys from the front half and its tweak keys from the back half.

CASCADES = (
  (("aes",     0, 1),),
  (("twofish", 0, 1),),
  (("serpent", 0, 1),),
  (("twofish", 0, 2), ("aes",     1, 3)),
  (("serpent", 0, 2), ("twofish", 1, 3)),
  (("aes",     0, 2), ("serpent", 1, 3)),
)

KEY_COUNT = 4


def module_constraints():
  return [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, data=None):
  return diskcryptor.generate_hash(CASCADES, KEY_COUNT, word, salt, data)


def module_verify_hash(line):
  return diskcryptor.verify_hash(CASCADES, KEY_COUNT, line)
