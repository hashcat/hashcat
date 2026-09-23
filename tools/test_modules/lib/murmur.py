#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# MurmurHash64A, for the 34xxx test modules. Perl computes it with Math::BigInt modulo 2^64, which
# the masks here reproduce.

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
