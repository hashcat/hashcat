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


# MurmurHash3 x86 32-bit, for mode 27800.

def murmur3_32(word, seed):
  c1, c2 = 0xcc9e2d51, 0x1b873593
  h = seed & 0xffffffff
  n = len(word)
  nblocks = n // 4

  for i in range(nblocks):
    k = int.from_bytes(word[i * 4:i * 4 + 4], "little")
    k = (k * c1) & 0xffffffff
    k = ((k << 15) | (k >> 17)) & 0xffffffff
    k = (k * c2) & 0xffffffff
    h ^= k
    h = ((h << 13) | (h >> 19)) & 0xffffffff
    h = (h * 5 + 0xe6546b64) & 0xffffffff

  tail = word[nblocks * 4:]
  k = 0

  for j in range(len(tail)):
    k ^= tail[j] << (8 * j)

  if tail:
    k = (k * c1) & 0xffffffff
    k = ((k << 15) | (k >> 17)) & 0xffffffff
    k = (k * c2) & 0xffffffff
    h ^= k

  h ^= n
  h ^= h >> 16
  h = (h * 0x85ebca6b) & 0xffffffff
  h ^= h >> 13
  h = (h * 0xc2b2ae35) & 0xffffffff
  h ^= h >> 16

  return h
