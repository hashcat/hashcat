#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# RIPEMD-128, RIPEMD-256 and the original 1992 RIPEMD, which is a different 128 bit hash from
# RIPEMD-128. Neither hashlib nor pycryptodome carries them, so this is a small self contained
# implementation of the reference algorithms.

import struct

_R = 0xffffffff


def _rol(x: int, n: int) -> int:
  return ((x << n) | (x >> (32 - n))) & _R


# RIPEMD-128 and RIPEMD-256 use the first 4 rounds of RIPEMD-160's word orders and shifts

_RL = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
]

_RR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
]

_SL = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
]

_SR = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
]

_KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc]
_KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x00000000]

# The original RIPEMD runs 3 rounds with the same order and shifts on both lines. Its second and
# third rounds differ from RIPEMD-160 in a few places, so they get their own tables.

_RO = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 14, 2, 11, 8,
  3, 10, 2, 4, 9, 15, 8, 1, 14, 7, 0, 6, 11, 13, 5, 12,
]

_SO = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 7, 11, 13, 12,
  11, 13, 14, 7, 14, 9, 13, 15, 6, 8, 13, 6, 12, 5, 7, 5,
]

_KO1 = [0x00000000, 0x5a827999, 0x6ed9eba1]
_KO2 = [0x50a28be6, 0x00000000, 0x5c4dd124]

_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def _f(j: int, x: int, y: int, z: int) -> int:
  if j == 0: return x ^ y ^ z
  if j == 1: return (x & y) | (~x & z)
  if j == 2: return (x | ~y) ^ z

  return (x & z) | (y & ~z)


def _fo(j: int, x: int, y: int, z: int) -> int:
  # the original RIPEMD: choice, majority, parity

  if j == 0: return (x & y) | (~x & z)
  if j == 1: return (x & y) | (x & z) | (y & z)

  return x ^ y ^ z


def _blocks(data: bytes):
  msg = data + b"\x80"
  msg += b"\x00" * ((56 - len(msg)) % 64)
  msg += struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff)

  for off in range(0, len(msg), 64):
    yield struct.unpack("<16I", msg[off:off + 64])


def _lines(hl: list, hr: list, x: tuple, swap: bool) -> tuple:
  al, bl, cl, dl = hl
  ar, br, cr, dr = hr

  for j in range(64):
    r = j >> 4

    t = _rol((al + _f(r, bl, cl, dl) + x[_RL[j]] + _KL[r]) & _R, _SL[j])
    al, bl, cl, dl = dl, t, bl, cl

    t = _rol((ar + _f(3 - r, br, cr, dr) + x[_RR[j]] + _KR[r]) & _R, _SR[j])
    ar, br, cr, dr = dr, t, br, cr

    if swap == False: continue

    if j == 15:
      al, ar = ar, al
    elif j == 31:
      bl, br = br, bl
    elif j == 47:
      cl, cr = cr, cl
    elif j == 63:
      dl, dr = dr, dl

  return (al, bl, cl, dl), (ar, br, cr, dr)


def rmd128(data: bytes) -> bytes:
  h = _IV[:]

  for x in _blocks(data):
    (al, bl, cl, dl), (ar, br, cr, dr) = _lines(h, h, x, False)

    h = [(h[1] + cl + dr) & _R, (h[2] + dl + ar) & _R, (h[3] + al + br) & _R, (h[0] + bl + cr) & _R]

  return struct.pack("<4I", *h)


def rmd256(data: bytes) -> bytes:
  h = _IV + [0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567]

  for x in _blocks(data):
    l, r = _lines(h[0:4], h[4:8], x, True)

    h = [(h[k] + l[k]) & _R for k in range(4)] + [(h[k + 4] + r[k]) & _R for k in range(4)]

  return struct.pack("<8I", *h)


def ripemd(data: bytes) -> bytes:
  h = _IV[:]

  for x in _blocks(data):
    a1, b1, c1, d1 = h
    a2, b2, c2, d2 = h

    for j in range(48):
      r = j >> 4

      t = _rol((a1 + _fo(r, b1, c1, d1) + x[_RO[j]] + _KO1[r]) & _R, _SO[j])
      a1, b1, c1, d1 = d1, t, b1, c1

      t = _rol((a2 + _fo(r, b2, c2, d2) + x[_RO[j]] + _KO2[r]) & _R, _SO[j])
      a2, b2, c2, d2 = d2, t, b2, c2

    h = [(h[1] + c1 + d2) & _R, (h[2] + d1 + a2) & _R, (h[3] + a1 + b2) & _R, (h[0] + b1 + c2) & _R]

  return struct.pack("<4I", *h)
