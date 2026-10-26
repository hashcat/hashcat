#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_word

# PKZIP master key: the ZipCrypto key schedule run over the password, the three 32 bit keys in hex.

TABLE = None


def _crc_table():
  global TABLE

  if TABLE is None:
    t = []
    for i in range(256):
      c = i
      for _ in range(8):
        c = (c >> 1) ^ (0xedb88320 if (c & 1) else 0)
      t.append(c)
    TABLE = t

  return TABLE


def _crc32(x, c):
  return ((x >> 8) ^ _crc_table()[(x ^ c) & 0xff]) & 0xffffffff


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

  for b in word:
    k0 = _crc32(k0, b)
    k1 = ((k1 + (k0 & 0xff)) * 0x08088405 + 1) & 0xffffffff
    k2 = _crc32(k2, (k1 >> 24) & 0xff)

  return "%08x%08x%08x" % (k0, k1, k2)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
