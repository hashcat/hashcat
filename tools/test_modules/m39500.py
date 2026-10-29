#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_salt_word

# XXH64 with the seed as the salt. The seed sets the initial state of the four lanes, so it is not
# the same as hashing a prefix. Both fields are the 64 bit value written as 16 hex digits.

MASK64 = 0xffffffffffffffff

PRIME64_1 = 0x9e3779b185ebca87
PRIME64_2 = 0xc2b2ae3d27d4eb4f
PRIME64_3 = 0x165667b19e3779f9
PRIME64_4 = 0x85ebca77c2b2ae63
PRIME64_5 = 0x27d4eb2f165667c5


def module_constraints():
  return [[0, 256], [16, 16], [0, 55], [16, 16], [-1, -1]]


def rotl64(x, r):
  return ((x << r) | (x >> (64 - r))) & MASK64


def xxh64_round(acc, lane):
  acc = (acc + lane * PRIME64_2) & MASK64
  acc = rotl64(acc, 31)

  return (acc * PRIME64_1) & MASK64


def xxh64_merge(acc, lane):
  acc ^= xxh64_round(0, lane)

  return (acc * PRIME64_1 + PRIME64_4) & MASK64


def xxh64(data, seed):
  data_len = len(data)

  pos = 0

  if data_len >= 32:
    v1 = (seed + PRIME64_1 + PRIME64_2) & MASK64
    v2 = (seed + PRIME64_2) & MASK64
    v3 = (seed + 0) & MASK64
    v4 = (seed - PRIME64_1) & MASK64

    while (pos + 32) <= data_len:
      v1 = xxh64_round(v1, int.from_bytes(data[pos +  0:pos +  8], "little"))
      v2 = xxh64_round(v2, int.from_bytes(data[pos +  8:pos + 16], "little"))
      v3 = xxh64_round(v3, int.from_bytes(data[pos + 16:pos + 24], "little"))
      v4 = xxh64_round(v4, int.from_bytes(data[pos + 24:pos + 32], "little"))

      pos += 32

    h = (rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)) & MASK64

    h = xxh64_merge(h, v1)
    h = xxh64_merge(h, v2)
    h = xxh64_merge(h, v3)
    h = xxh64_merge(h, v4)
  else:
    h = (seed + PRIME64_5) & MASK64

  h = (h + data_len) & MASK64

  while (pos + 8) <= data_len:
    h ^= xxh64_round(0, int.from_bytes(data[pos:pos + 8], "little"))
    h = (rotl64(h, 27) * PRIME64_1 + PRIME64_4) & MASK64

    pos += 8

  if (pos + 4) <= data_len:
    h ^= (int.from_bytes(data[pos:pos + 4], "little") * PRIME64_1) & MASK64
    h = (rotl64(h, 23) * PRIME64_2 + PRIME64_3) & MASK64

    pos += 4

  while pos < data_len:
    h ^= (data[pos] * PRIME64_5) & MASK64
    h = (rotl64(h, 11) * PRIME64_1) & MASK64

    pos += 1

  h ^= h >> 33
  h = (h * PRIME64_2) & MASK64
  h ^= h >> 29
  h = (h * PRIME64_3) & MASK64
  h ^= h >> 32

  return h


def module_generate_hash(word, salt, iterations=None):
  seed = int(salt, 16)

  return "%016x:%016x" % (xxh64(word, seed), seed)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
