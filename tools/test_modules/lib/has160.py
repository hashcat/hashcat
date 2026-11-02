#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# HAS-160, the Korean KCDSA hash derived from SHA-1. Neither hashlib nor pycryptodome carries it,
# so this is a small self contained implementation following rhash's has160.c.

import struct

_R = 0xffffffff

# per round: the message word order (16 to 31 are the XOR combined words) and the left rotation
# that B gets after every step

_ORDER = [
  [18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15],
  [22, 3, 6, 9, 12, 23, 15, 2, 5, 8, 20, 11, 14, 1, 4, 21, 7, 10, 13, 0],
  [26, 12, 5, 14, 7, 27, 0, 9, 2, 11, 24, 4, 13, 6, 15, 25, 8, 1, 10, 3],
  [30, 7, 2, 13, 8, 31, 3, 14, 9, 4, 28, 15, 10, 5, 0, 29, 11, 6, 1, 12],
]

_ROT = [5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13]

_K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc]

_BROT = [10, 17, 25, 30]

# the 16 extra words, each the XOR of 4 message words

_MIX = [
  (0, 1, 2, 3), (4, 5, 6, 7), (8, 9, 10, 11), (12, 13, 14, 15),
  (3, 6, 9, 12), (2, 5, 8, 15), (1, 4, 11, 14), (0, 7, 10, 13),
  (5, 7, 12, 14), (0, 2, 9, 11), (4, 6, 13, 15), (1, 3, 8, 10),
  (2, 7, 8, 13), (3, 4, 9, 14), (0, 5, 10, 15), (1, 6, 11, 12),
]


def _rol(x: int, n: int) -> int:
  r = ((x << n) | (x >> (32 - n))) & _R

  return r


def _f(rnd: int, b: int, c: int, d: int) -> int:
  if rnd == 0: return d ^ (b & (c ^ d))
  if rnd == 2: return c ^ (b | (~d & _R))

  return b ^ c ^ d


def _block(h: list, blk: bytes) -> list:
  x = list(struct.unpack("<16I", blk))

  for m in _MIX: x.append(x[m[0]] ^ x[m[1]] ^ x[m[2]] ^ x[m[3]])

  a, b, c, d, e = h

  for rnd in range(4):
    order = _ORDER[rnd]
    k     = _K[rnd]
    brot  = _BROT[rnd]

    for j in range(20):
      t = (e + _rol(a, _ROT[j]) + _f(rnd, b, c, d) + x[order[j]] + k) & _R

      a, b, c, d, e = t, a, _rol(b, brot), c, d

  out = [(h[0] + a) & _R, (h[1] + b) & _R, (h[2] + c) & _R, (h[3] + d) & _R, (h[4] + e) & _R]

  return out


def has160(data: bytes) -> bytes:
  h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

  msg = data + b"\x80"
  msg += b"\x00" * ((56 - len(msg)) % 64)
  msg += struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff)

  for off in range(0, len(msg), 64): h = _block(h, msg[off:off + 64])

  digest = struct.pack("<5I", *h)

  return digest
