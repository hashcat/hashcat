#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import diskcryptor

# DiskCryptor with a 1536 bit key: up to three ciphers, so six 256 bit keys.

CASCADES = (
  (("aes",     0, 1),),
  (("twofish", 0, 1),),
  (("serpent", 0, 1),),
  (("twofish", 0, 2), ("aes",     1, 3)),
  (("serpent", 0, 2), ("twofish", 1, 3)),
  (("aes",     0, 2), ("serpent", 1, 3)),
  (("serpent", 0, 3), ("twofish", 1, 4), ("aes", 2, 5)),
)

KEY_COUNT = 6


def module_constraints():
  return [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, data=None):
  return diskcryptor.generate_hash(CASCADES, KEY_COUNT, word, salt, data)


def module_verify_hash(line):
  return diskcryptor.verify_hash(CASCADES, KEY_COUNT, line)
