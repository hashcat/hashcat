#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Luffa (the version submitted to the second SHA-3 round), with 224, 256, 384 and 512 bit digests.
# Neither hashlib nor pycryptodome carries it.

import struct

_R = 0xffffffff

_IV = [
  [0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465, 0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb],
  [0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3, 0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581],
  [0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05, 0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7],
  [0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67, 0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce],
  [0x6c68e9be, 0x5ec41e22, 0xc825b7c7, 0xaffb4363, 0xf5df3999, 0x0fc688f1, 0xb07224cc, 0x03e86cea],
]

# step constants per lane, added to words 0 and 4 after each of the 8 steps

_RC0 = [
  [0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e, 0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12],
  [0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51, 0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e],
  [0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a, 0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434],
  [0xb213afa5, 0xc84ebe95, 0x4e608a22, 0x56d858fe, 0x343b138f, 0xd0ec4e3d, 0x2ceb4882, 0xb3ad2208],
  [0xf0d2e9e3, 0xac11d7fa, 0x1bcb66f2, 0x6f2d9bc9, 0x78602649, 0x8edae952, 0x3b6ba548, 0xedae9520],
]

_RC4 = [
  [0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f, 0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d],
  [0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28, 0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704],
  [0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7, 0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7],
  [0xe028c9bf, 0x44756f91, 0x7e8fce32, 0x956548be, 0xfe191be2, 0x3cb226e5, 0x5944a28e, 0xa1c4c355],
  [0x5090d577, 0x2d1925ab, 0xb46496ac, 0xd1925ab0, 0x29131ab6, 0x0fc053c3, 0x3f014f0c, 0xfc053c31],
]


def _rol(x: int, n: int) -> int:
  r = ((x << n) | (x >> (32 - n))) & _R

  return r


def _m2(s: list) -> list:
  # multiplication by 2 in GF(2^8)[x] modulo the Luffa polynomial

  t = s[7]

  r = [t, s[0] ^ t, s[1], s[2] ^ t, s[3] ^ t, s[4], s[5], s[6]]

  return r


def _xor(a: list, b: list) -> list:
  r = [x ^ y for x, y in zip(a, b)]

  return r


def _mi(v: list, m: list) -> list:
  w = len(v)

  a = v[0]

  for i in range(1, w): a = _xor(a, v[i])

  a = _m2(a)

  v = [_xor(x, a) for x in v]

  if w == 4:
    b = _xor(_m2(v[0]), v[3])

    v[3] = _xor(_m2(v[3]), v[2])
    v[2] = _xor(_m2(v[2]), v[1])
    v[1] = _xor(_m2(v[1]), v[0])
    v[0] = b
  elif w == 5:
    b = _xor(_m2(v[0]), v[1])

    v[1] = _xor(_m2(v[1]), v[2])
    v[2] = _xor(_m2(v[2]), v[3])
    v[3] = _xor(_m2(v[3]), v[4])
    v[4] = _xor(_m2(v[4]), v[0])
    v[0] = _xor(_m2(b), v[4])
    v[4] = _xor(_m2(v[4]), v[3])
    v[3] = _xor(_m2(v[3]), v[2])
    v[2] = _xor(_m2(v[2]), v[1])
    v[1] = _xor(_m2(v[1]), b)

  v[0] = _xor(v[0], m)

  for i in range(1, w):
    m = _m2(m)

    v[i] = _xor(v[i], m)

  return v


def _crumb(a0: int, a1: int, a2: int, a3: int):
  t = a0

  a0 |= a1
  a2 ^= a3
  a1 ^= _R
  a0 ^= a3
  a3 &= t
  a1 ^= a3
  a3 ^= a2
  a2 &= a0
  a0 ^= _R
  a2 ^= a1
  a1 |= a3
  t  ^= a1
  a3 ^= a2
  a2 &= a1
  a1 ^= a0

  return t, a1, a2, a3


def _mix(u: int, v: int):
  v ^= u
  u  = _rol(u,  2) ^ v
  v  = _rol(v, 14) ^ u
  u  = _rol(u, 10) ^ v
  v  = _rol(v,  1)

  return u, v


def _q(j: int, v: list) -> list:
  x0, x1, x2, x3, x4, x5, x6, x7 = v

  # the tweak rotates the second half of lane j left by j

  if j > 0:
    x4 = _rol(x4, j)
    x5 = _rol(x5, j)
    x6 = _rol(x6, j)
    x7 = _rol(x7, j)

  rc0 = _RC0[j]
  rc4 = _RC4[j]

  for r in range(8):
    x0, x1, x2, x3 = _crumb(x0, x1, x2, x3)
    x5, x6, x7, x4 = _crumb(x5, x6, x7, x4)

    x0, x4 = _mix(x0, x4)
    x1, x5 = _mix(x1, x5)
    x2, x6 = _mix(x2, x6)
    x3, x7 = _mix(x3, x7)

    x0 ^= rc0[r]
    x4 ^= rc4[r]

  return [x0, x1, x2, x3, x4, x5, x6, x7]


def _round(v: list, block: bytes) -> list:
  v = _mi(v, list(struct.unpack(">8I", block)))

  r = [_q(j, v[j]) for j in range(len(v))]

  return r


def _out(v: list) -> bytes:
  h = v[0]

  for i in range(1, len(v)): h = _xor(h, v[i])

  r = struct.pack(">8I", *h)

  return r


def _luffa(data: bytes, w: int, size: int) -> bytes:
  v = [list(x) for x in _IV[:w]]

  msg = data + b"\x80"
  msg += bytes((32 - len(msg)) % 32)

  for off in range(0, len(msg), 32):
    v = _round(v, msg[off:off + 32])

  # blank rounds squeeze out 256 bits each

  out = b""

  while len(out) < size:
    v = _round(v, bytes(32))

    out += _out(v)

  r = out[:size]

  return r


def luffa224(data: bytes) -> bytes:
  return _luffa(data, 3, 28)


def luffa256(data: bytes) -> bytes:
  return _luffa(data, 3, 32)


def luffa384(data: bytes) -> bytes:
  return _luffa(data, 4, 48)


def luffa512(data: bytes) -> bytes:
  return _luffa(data, 5, 64)
