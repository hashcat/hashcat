#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_word

# MurmurHash64A, the 64 bit variant, over a big endian 8 byte seed. Perl uses Math::BigInt modulo
# 2^64, which is what the masks here reproduce.

M = 0xc6a4a7935bd1e995
R = 47
MASK = 0xffffffffffffffff


def murmur64a(word, seed):
  n = len(word)

  h = seed ^ ((n * M) & MASK)

  end = n - (n & 7)

  for i in range(0, end, 8):
    k = int.from_bytes(word[i:i + 8], "little")
    k = (k * M) & MASK
    k ^= k >> R
    k = (k * M) & MASK
    h ^= k
    h = (h * M) & MASK

  rem = n & 7
  tail = word[end:]

  for j in range(rem - 1, -1, -1):
    h ^= tail[j] << (8 * j)

  if rem:
    h = (h * M) & MASK

  h ^= h >> R
  h = (h * M) & MASK
  h ^= h >> R

  return h


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  seed = int.from_bytes(bytes.fromhex(salt), "big")

  return "%016x:%016x" % (murmur64a(word, seed), seed)


def module_verify_hash(line):
  parts = line.split(b":", 2)

  if len(parts) != 3 or len(parts[0]) != 16 or len(parts[1]) != 16:
    return None

  _, seed, word = parts

  try:
    return (module_generate_hash(word, seed.decode()), word)
  except ValueError:
    return None
