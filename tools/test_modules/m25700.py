#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_salt_word

# Jenkins/tanjent MurmurHash, the variant hashcat uses: seed + 0xdeadbeef, a multiply-xor per 32 bit
# little endian word, then two finalizing rounds. Perl computes it with "use integer" (64 bit signed,
# wrapping); here every step is kept modulo 2^64, which gives the same low bits.

M = 0x7fd652ad
MASK64 = 0xffffffffffffffff


def murmur(word, seed):
  h = (seed + 0xdeadbeef) & MASK64

  n = len(word)

  i = 0

  while i < n - 3:
    l = word[i] | (word[i + 1] << 8) | (word[i + 2] << 16) | (word[i + 3] << 24)
    h = (h + l) & MASK64
    h = (h * M) & MASK64
    h ^= (h & 0xffffffff) >> 16
    i += 4

  rem = n & 3

  if rem:
    l = 0
    for k in range(rem):
      l |= word[i + k] << (8 * k)
    h = (h + l) & MASK64
    h = (h * M) & MASK64
    h ^= (h & 0xffffffff) >> 16

  h = (h * M) & MASK64
  h ^= (h & 0xffffffff) >> 10
  h = (h * M) & MASK64
  h ^= (h & 0xffffffff) >> 17

  return h & 0xffffffff


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 55], [8, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  seed = int.from_bytes(bytes.fromhex(salt), "big")

  return "%08x:%08x" % (murmur(word, seed), seed)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, salt, word = parts

  if len(hash_in) != 8 or len(salt) != 8:
    return None

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
