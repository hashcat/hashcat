#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_salt_word

# XXH32 with the seed as the salt. The seed sets the initial state of the four lanes, so it is not
# the same as hashing a prefix. Both fields are the 32 bit value written as 8 hex digits.

MASK32 = 0xffffffff

PRIME32_1 = 0x9e3779b1
PRIME32_2 = 0x85ebca77
PRIME32_3 = 0xc2b2ae3d
PRIME32_4 = 0x27d4eb2f
PRIME32_5 = 0x165667b1


def module_constraints():
  return [[0, 256], [8, 8], [0, 55], [8, 8], [-1, -1]]


def rotl32(x, r):
  return ((x << r) | (x >> (32 - r))) & MASK32


def xxh32_round(acc, lane):
  acc = (acc + lane * PRIME32_2) & MASK32
  acc = rotl32(acc, 13)

  return (acc * PRIME32_1) & MASK32


def xxh32(data, seed):
  data_len = len(data)

  pos = 0

  if data_len >= 16:
    v1 = (seed + PRIME32_1 + PRIME32_2) & MASK32
    v2 = (seed + PRIME32_2) & MASK32
    v3 = (seed + 0) & MASK32
    v4 = (seed - PRIME32_1) & MASK32

    while (pos + 16) <= data_len:
      v1 = xxh32_round(v1, int.from_bytes(data[pos +  0:pos +  4], "little"))
      v2 = xxh32_round(v2, int.from_bytes(data[pos +  4:pos +  8], "little"))
      v3 = xxh32_round(v3, int.from_bytes(data[pos +  8:pos + 12], "little"))
      v4 = xxh32_round(v4, int.from_bytes(data[pos + 12:pos + 16], "little"))

      pos += 16

    h = (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) & MASK32
  else:
    h = (seed + PRIME32_5) & MASK32

  h = (h + data_len) & MASK32

  while (pos + 4) <= data_len:
    h = (h + int.from_bytes(data[pos:pos + 4], "little") * PRIME32_3) & MASK32
    h = (rotl32(h, 17) * PRIME32_4) & MASK32

    pos += 4

  while pos < data_len:
    h = (h + data[pos] * PRIME32_5) & MASK32
    h = (rotl32(h, 11) * PRIME32_1) & MASK32

    pos += 1

  h ^= h >> 15
  h = (h * PRIME32_2) & MASK32
  h ^= h >> 13
  h = (h * PRIME32_3) & MASK32
  h ^= h >> 16

  return h


def module_generate_hash(word, salt, iterations=None):
  seed = int(salt, 16)

  return "%08x:%08x" % (xxh32(word, seed), seed)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
