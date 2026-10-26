#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Groestl-224/256/384/512, the final round version. Neither hashlib nor pycryptodome carries it, so
# this is a small self contained implementation of the reference algorithm.

import struct

_M64 = 0xffffffffffffffff

_SBOX = bytes.fromhex(
  "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
  "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
  "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
  "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
  "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
  "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
  "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
  "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)


def _gmul(a, b):
  r = 0

  while b > 0:
    if (b & 1) == 1: r ^= a

    a <<= 1

    if (a & 0x100) != 0: a ^= 0x11b

    b >>= 1

  return r


def _make_tables():
  v = [2, 2, 3, 4, 5, 3, 5, 7]

  tables = []

  for k in range(8):
    t = []

    for x in range(256):
      s = _SBOX[x]
      w = 0

      for r in range(8):
        w |= _gmul(v[(k - r) % 8], s) << (56 - 8 * r)

      t.append(w)

    tables.append(t)

  return tables


_T = _make_tables()

_SHIFT_P_SMALL = [0, 1, 2, 3, 4, 5, 6, 7]
_SHIFT_Q_SMALL = [1, 3, 5, 7, 0, 2, 4, 6]
_SHIFT_P_BIG   = [0, 1, 2, 3, 4, 5, 6, 11]
_SHIFT_Q_BIG   = [1, 3, 5, 11, 0, 2, 4, 6]


def _perm(a, q, rounds, shift):
  cols = len(a)

  t0, t1, t2, t3, t4, t5, t6, t7 = _T
  s0, s1, s2, s3, s4, s5, s6, s7 = shift

  for r in range(rounds):
    if q == True:
      a = [a[j] ^ _M64 ^ ((j << 4) ^ r) for j in range(cols)]
    else:
      a = [a[j] ^ (((j << 4) ^ r) << 56) for j in range(cols)]

    b = []

    for j in range(cols):
      w = t0[(a[(j + s0) % cols] >> 56) & 0xff]

      w ^= t1[(a[(j + s1) % cols] >> 48) & 0xff]
      w ^= t2[(a[(j + s2) % cols] >> 40) & 0xff]
      w ^= t3[(a[(j + s3) % cols] >> 32) & 0xff]
      w ^= t4[(a[(j + s4) % cols] >> 24) & 0xff]
      w ^= t5[(a[(j + s5) % cols] >> 16) & 0xff]
      w ^= t6[(a[(j + s6) % cols] >>  8) & 0xff]
      w ^= t7[(a[(j + s7) % cols] >>  0) & 0xff]

      b.append(w)

    a = b

  return a


def _groestl(data, out_len):
  big = out_len > 32

  bs     = 128 if big else 64
  cols   = bs // 8
  rounds = 14 if big else 10
  sp     = _SHIFT_P_BIG if big else _SHIFT_P_SMALL
  sq     = _SHIFT_Q_BIG if big else _SHIFT_Q_SMALL

  h = [0] * cols

  h[cols - 1] = out_len * 8

  # 0x80, zeros, then the 64-bit big-endian count of blocks including the padding

  rem    = len(data) % bs
  padlen = bs - rem if (bs - rem) >= 9 else 2 * bs - rem
  blocks = (len(data) + padlen) // bs

  msg = data + b"\x80" + bytes(padlen - 9) + struct.pack(">Q", blocks)

  fmt = ">%dQ" % cols

  for off in range(0, len(msg), bs):
    m = struct.unpack_from(fmt, msg, off)

    p = _perm([h[j] ^ m[j] for j in range(cols)], False, rounds, sp)
    q = _perm(list(m), True, rounds, sq)

    h = [h[j] ^ p[j] ^ q[j] for j in range(cols)]

  p = _perm(h, False, rounds, sp)

  out = struct.pack(fmt, *[h[j] ^ p[j] for j in range(cols)])

  return out[bs - out_len:]


def groestl224(data: bytes) -> bytes:
  return _groestl(bytes(data), 28)


def groestl256(data: bytes) -> bytes:
  return _groestl(bytes(data), 32)


def groestl384(data: bytes) -> bytes:
  return _groestl(bytes(data), 48)


def groestl512(data: bytes) -> bytes:
  return _groestl(bytes(data), 64)
