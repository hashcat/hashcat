#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# SIMD (the tweaked version from the second SHA-3 round), with 224, 256, 384 and 512 bit digests,
# matching sphlib. Neither hashlib nor pycryptodome carries it.

import operator
import struct

_R = 0xffffffff

_IV224 = [
  0x33586e9f, 0x12fff033, 0xb2d9f64d, 0x6f8fea53, 0xde943106, 0x2742e439, 0x4fbab5ac, 0x62b9ff96,
  0x22e7b0af, 0xc862b3a8, 0x33e00cdc, 0x236b86a6, 0xf64ae77c, 0xfa373b76, 0x7dc1ee5b, 0x7fb29ce8,
]

_IV256 = [
  0x4d567983, 0x07190ba9, 0x8474577b, 0x39d726e9, 0xaaf3d925, 0x3ee20b03, 0xafd5e751, 0xc96006d3,
  0xc2c2ba14, 0x49b3bcb4, 0xf67caf46, 0x668626c9, 0xe2eaa8d2, 0x1ff47833, 0xd0c661a5, 0x55693de1,
]

_IV384 = [
  0x8a36eebc, 0x94a3bd90, 0xd1537b83, 0xb25b070b, 0xf463f1b5, 0xb6f81e20, 0x0055c339, 0xb4d144d1,
  0x7360ca61, 0x18361a03, 0x17dcb4b9, 0x3414c45a, 0xa699a9d2, 0xe39e9664, 0x468bfe77, 0x51d062f8,
  0xb9e3bfe8, 0x63bece2a, 0x8fe506b9, 0xf8cc4ac2, 0x7ae11542, 0xb1aadda1, 0x64b06794, 0x28d2f462,
  0xe64071ec, 0x1deb91a8, 0x8ac8db23, 0x3f782ab5, 0x039b5cb8, 0x71ddd962, 0xfade2cea, 0x1416df71,
]

_IV512 = [
  0x0ba16b95, 0x72f999ad, 0x9fecc2ae, 0xba3264fc, 0x5e894929, 0x8e9f30e5, 0x2f1daa37, 0xf0f2c558,
  0xac506643, 0xa90635a5, 0xe25b878b, 0xaab7878f, 0x88817f7a, 0x0a02892b, 0x559a7550, 0x598f657e,
  0x7eef60a1, 0x6b70e3e8, 0x9c1714d1, 0xb958e2a8, 0xab02675e, 0xed1c014f, 0xcd8d65bb, 0xfdb7a257,
  0x09254899, 0xd699c7bc, 0x9019b6dc, 0x2b9022e4, 0x8fa14956, 0x21bf9bd3, 0xb94d0943, 0x6ffddc22,
]


def _rol(x: int, n: int) -> int:
  r = ((x << n) | (x >> (32 - n))) & _R

  return r


class _Variant:
  # n words per state row, so a block of 16 * n bytes and an NTT of 32 * n points over GF(257)

  def __init__(self, n: int, xor_seq: list, xor_start: list, xor_final: list, offsets: list):
    self.n = n
    self.block = 16 * n
    self.points = 32 * n

    root = pow(41, 256 // self.points, 257)

    self.ntt = [[pow(root, i * j, 257) for j in range(self.block)] for i in range(self.points)]

    # the expansion adds X^(points-1) to every block and also X^(points-3) to the final one

    top = self.points - 1

    self.yoff_n = [pow(root, top * i, 257) for i in range(self.points)]
    self.yoff_f = [(y + pow(root, (top - 2) * i, 257)) % 257 for i, y in enumerate(self.yoff_n)]

    # step k of round r swaps the rotated A words by XOR with xor_seq[xor_start[r] + k]

    self.xor_round = [xor_seq[i:i + 8] for i in xor_start]
    self.xor_final = xor_final
    self.offsets = offsets


_SMALL = _Variant(4, [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2], [0, 2, 1, 0], [3, 1, 2, 3],
                  [(0, 1, 185), (0, 1, 185), (-128, -64, 233), (-191, -127, 233)])

_BIG = _Variant(8, [1, 6, 2, 3, 5, 7, 4, 1, 6, 2, 3], [0, 1, 2, 3], [5, 7, 4, 1],
                [(0, 1, 185), (0, 1, 185), (-256, -128, 233), (-383, -255, 233)])

# order in which the 32 groups of expanded words feed the 32 steps

_WP = [
  4, 6, 0, 2, 7, 5, 3, 1, 15, 11, 12, 8, 9, 13, 10, 14,
  17, 18, 23, 20, 22, 21, 16, 19, 30, 24, 25, 31, 27, 29, 28, 26,
]

_ROT = [(3, 23, 17, 27), (28, 19, 22, 7), (29, 9, 15, 5), (4, 13, 10, 25)]


def _step(st: list, w: list, maj: bool, r: int, s: int, p: int) -> None:
  a, b, c, d = st

  n = len(a)

  ta = [_rol(x, r) for x in a]

  for i in range(n):
    if maj == True:
      f = (a[i] & b[i]) | ((a[i] | b[i]) & c[i])
    else:
      f = ((b[i] ^ c[i]) & a[i]) ^ c[i]

    tt = (d[i] + w[i] + f) & _R

    a[i] = (_rol(tt, s) + ta[i ^ p]) & _R

  st[0], st[1], st[2], st[3] = a, ta, b, c


def _compress(v: _Variant, h: list, block: bytes, final: bool) -> list:
  n = v.n

  yoff = v.yoff_n

  if final == True: yoff = v.yoff_f

  q = []

  for i in range(v.points):
    t = (sum(map(operator.mul, v.ntt[i], block)) + yoff[i]) % 257

    if t > 128: t -= 257

    q.append(t)

  m = struct.unpack("<%dI" % (4 * n), block)

  x = [h[i] ^ m[i] for i in range(4 * n)]

  st = [x[0:n], x[n:2 * n], x[2 * n:3 * n], x[3 * n:4 * n]]

  for rnd in range(4):
    o1, o2, mm = v.offsets[rnd]

    rot = _ROT[rnd]

    for k in range(8):
      base = _WP[rnd * 8 + k] * 2 * n

      lo = [(q[base + 2 * i + o1] * mm) & 0xffff for i in range(n)]
      hi = [(q[base + 2 * i + o2] * mm) & 0xffff for i in range(n)]

      w = [lw + (hw << 16) for lw, hw in zip(lo, hi)]

      _step(st, w, k >= 4, rot[k % 4], rot[(k + 1) % 4], v.xor_round[rnd][k])

  # 4 more steps take the previous chaining value as their message words

  for k in range(4):
    _step(st, h[k * n:(k + 1) * n], False, _ROT[3][k], _ROT[3][(k + 1) % 4], v.xor_final[k])

  r = st[0] + st[1] + st[2] + st[3]

  return r


def _simd(data: bytes, v: _Variant, iv: list, words: int) -> bytes:
  bs = v.block

  h = list(iv)

  # zero padding without a marker bit, the bit length goes into a final block of its own

  msg = data + bytes((bs - len(data)) % bs)

  for off in range(0, len(msg), bs):
    h = _compress(v, h, msg[off:off + bs], False)

  last = struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff) + bytes(bs - 8)

  h = _compress(v, h, last, True)

  r = struct.pack("<%dI" % words, *h[:words])

  return r


def simd224(data: bytes) -> bytes:
  return _simd(data, _SMALL, _IV224, 7)


def simd256(data: bytes) -> bytes:
  return _simd(data, _SMALL, _IV256, 8)


def simd384(data: bytes) -> bytes:
  return _simd(data, _BIG, _IV384, 12)


def simd512(data: bytes) -> bytes:
  return _simd(data, _BIG, _IV512, 16)
