#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# MD5 compression over a single chosen block, for the modes that read the raw state words back
# without the length padding or finalisation a normal MD5 does (CRAM-MD5, 16400). hashlib gives no
# way to reach the compression function on its own.

M = 0xffffffff

_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

_K = [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def _rol(x, n):
  return ((x << n) | (x >> (32 - n))) & M


def compress(state, block):
  # state is the four 32 bit words, block is exactly 64 bytes; returns the new four words

  w = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]

  a, b, c, d = state

  for i in range(64):
    if i < 16:
      f = (b & c) | (~b & d)
      g = i
    elif i < 32:
      f = (d & b) | (~d & c)
      g = (5 * i + 1) & 15
    elif i < 48:
      f = b ^ c ^ d
      g = (3 * i + 5) & 15
    else:
      f = c ^ (b | (~d & M))
      g = (7 * i) & 15

    tmp = d
    d = c
    c = b
    b = (b + _rol((a + f + _K[i] + w[g]) & M, _S[i])) & M
    a = tmp

  return [(x + y) & M for x, y in zip(state, (a, b, c, d))]


def compress_words(block):
  # one block from the MD5 IV, returned as the four state words in little-endian bytes, with no
  # length padding and no finalisation

  state = compress(list(IV), block)

  return b"".join(x.to_bytes(4, "little") for x in state)
