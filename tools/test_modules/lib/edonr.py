#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# EDON-R 256 and 512, the SHA-3 candidate built on quasigroup operations. Neither hashlib nor
# pycryptodome carries it, so this follows rhash's edonr.c.

import struct


class _Param:
  def __init__(self, bits: int, rot1: list, rot2: list, c1: int, c2: int, h0: list, fmt: str):
    self.mask = (1 << bits) - 1
    self.bits = bits
    self.rot1 = rot1
    self.rot2 = rot2
    self.c1   = c1
    self.c2   = c2
    self.h0   = h0
    self.fmt  = fmt


_P256 = _Param(32, [5, 11, 13, 17, 19, 29, 31], [3, 7, 11, 17, 19, 23, 29], 0xaaaaaaaa, 0x55555555,
  [0x40414243 + 0x04040404 * i for i in range(16)], "<16I")

_P512 = _Param(64, [5, 19, 29, 31, 41, 57, 61], [3, 17, 23, 31, 37, 45, 59], 0xaaaaaaaaaaaaaaaa,
  0x5555555555555555, [0x8081828384858687 + 0x0808080808080808 * i for i in range(16)], "<16Q")


def _q(p: _Param, x: list, y: list) -> list:
  # the quasigroup operation of two 8 word vectors, from the eBASH submission

  m  = p.mask
  w  = p.bits
  r1 = p.rot1
  r2 = p.rot2

  def rol(v, n):
    v &= m

    r = ((v << n) | (v >> (w - n))) & m

    return r

  x0, x1, x2, x3, x4, x5, x6, x7 = x
  y0, y1, y2, y3, y4, y5, y6, y7 = y

  t8  = x0 + x4
  t9  = x1 + x7
  t12 = t8 + t9
  t10 = x2 + x3
  t11 = x5 + x6
  t13 = t10 + t11

  t0 = (p.c1 + t12 + x2) & m
  t1 = rol(t12 + x3, r1[0])
  t2 = rol(t12 + x6, r1[1])
  t3 = rol(t13 + x7, r1[2])
  t4 = rol(x1 + t13, r1[3])
  t5 = rol(t8 + t10 + x5, r1[4])
  t6 = rol(x0 + t9 + t11, r1[5])
  t7 = rol(t13 + x4, r1[6])

  t16 = t0 ^ t4
  t17 = t1 ^ t7
  t18 = t2 ^ t3
  t19 = t5 ^ t6

  s8  = t3 ^ t19
  s9  = t2 ^ t19
  s10 = t18 ^ t5
  s11 = t16 ^ t1
  s12 = t16 ^ t7
  s13 = t17 ^ t6
  s14 = t18 ^ t4
  s15 = t0 ^ t17

  u16 = y0 + y1
  u17 = y2 + y5
  u20 = u16 + u17
  u18 = y3 + y4
  u22 = u16 + u18
  u19 = y6 + y7
  u21 = u18 + u19
  u23 = u17 + u19

  t0 = (p.c2 + u20 + y7) & m
  t1 = rol(u22 + y6, r2[0])
  t2 = rol(u20 + y3, r2[1])
  t3 = rol(y2 + u21, r2[2])
  t4 = rol(u22 + y5, r2[3])
  t5 = rol(u23 + y4, r2[4])
  t6 = rol(y1 + u23, r2[5])
  t7 = rol(y0 + u21, r2[6])

  t16 = t0 ^ t1
  t17 = t2 ^ t5
  t18 = t3 ^ t4
  t19 = t6 ^ t7

  z = [
    (s11 + (t16 ^ t5)) & m,
    (s12 + (t2 ^ t19)) & m,
    (s13 + (t16 ^ t3)) & m,
    (s14 + (t0 ^ t18)) & m,
    (s15 + (t1 ^ t17)) & m,
    (s8 + (t18 ^ t6)) & m,
    (s9 + (t17 ^ t7)) & m,
    (s10 + (t4 ^ t19)) & m,
  ]

  return z


def _block(p: _Param, h: list, b: list) -> list:
  p16 = _q(p, b[15:7:-1], b[0:8])
  p24 = _q(p, p16, b[8:16])

  p16 = _q(p, h[8:16], p16)
  p24 = _q(p, p16, p24)

  p16 = _q(p, p16, h[0:8])
  p24 = _q(p, p24, p16)

  lo = _q(p, b[7::-1], p16)
  hi = _q(p, lo, p24)

  out = lo + hi

  return out


def _edonr(p: _Param, data: bytes) -> bytes:
  bs = 8 * p.bits // 4

  # 0x80, zero fill, then the bit length as a little endian 64 bit word ending the block

  msg = data + b"\x80"
  msg += b"\x00" * ((bs - 8 - len(msg)) % bs)
  msg += struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff)

  h = list(p.h0)

  for off in range(0, len(msg), bs): h = _block(p, h, list(struct.unpack(p.fmt, msg[off:off + bs])))

  digest = struct.pack(p.fmt[0] + "8" + p.fmt[-1], *h[8:16])

  return digest


def edon256(data: bytes) -> bytes:
  digest = _edonr(_P256, data)

  return digest


def edon512(data: bytes) -> bytes:
  digest = _edonr(_P512, data)

  return digest
