#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_salt_word

# Bob Jenkins' lookup8 hash () with the level as the salt. The level starts two of the three lanes,
# so it is not the same as hashing a prefix. Both fields are the 64 bit value written as 16 hex
# digits.

MASK64 = 0xffffffffffffffff

GOLDEN = 0x9e3779b97f4a7c13


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [16, 16],
      },
      'combined_length': None,
    },
  }


def mix64(a, b, c):
  a = (a - b - c) & MASK64; a ^= c >> 43
  b = (b - c - a) & MASK64; b ^= (a << 9) & MASK64
  c = (c - a - b) & MASK64; c ^= b >> 8
  a = (a - b - c) & MASK64; a ^= c >> 38
  b = (b - c - a) & MASK64; b ^= (a << 23) & MASK64
  c = (c - a - b) & MASK64; c ^= b >> 5
  a = (a - b - c) & MASK64; a ^= c >> 35
  b = (b - c - a) & MASK64; b ^= (a << 49) & MASK64
  c = (c - a - b) & MASK64; c ^= b >> 11
  a = (a - b - c) & MASK64; a ^= c >> 12
  b = (b - c - a) & MASK64; b ^= (a << 18) & MASK64
  c = (c - a - b) & MASK64; c ^= b >> 22

  return a, b, c


def lookup8(data, level):
  data_len = len(data)

  a = level
  b = level
  c = GOLDEN

  pos = 0

  while (data_len - pos) >= 24:
    a = (a + int.from_bytes(data[pos +  0:pos +  8], "little")) & MASK64
    b = (b + int.from_bytes(data[pos +  8:pos + 16], "little")) & MASK64
    c = (c + int.from_bytes(data[pos + 16:pos + 24], "little")) & MASK64

    a, b, c = mix64(a, b, c)

    pos += 24

  # the tail fills a, then b, then c from its second byte up, because the length takes the first

  tail = data[pos:] + bytes(24 - (data_len - pos))

  c = (c + data_len) & MASK64

  a = (a + int.from_bytes(tail[ 0: 8], "little")) & MASK64
  b = (b + int.from_bytes(tail[ 8:16], "little")) & MASK64
  c = (c + ((int.from_bytes(tail[16:24], "little") << 8) & MASK64)) & MASK64

  a, b, c = mix64(a, b, c)

  return c


def module_generate_hash(word, salt, iterations=None):
  level = int(salt, 16)

  hash_value = lookup8(word, level)

  return "%016x:%016x" % (hash_value, level)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
