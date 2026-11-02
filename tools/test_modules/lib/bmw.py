#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# BMW-224, BMW-256, BMW-384 and BMW-512 (Blue Midnight Wish, SHA-3 round 2). Neither hashlib nor
# pycryptodome carries it, so this is a small self contained implementation.

import struct

# W[i] = sum of +-(M[j] ^ H[j]) over these five indices, the first term is always added

_W = [
  ((5, 1), (7, -1), (10, 1), (13, 1), (14, 1)),
  ((6, 1), (8, -1), (11, 1), (14, 1), (15, -1)),
  ((0, 1), (7, 1), (9, 1), (12, -1), (15, 1)),
  ((0, 1), (1, -1), (8, 1), (10, -1), (13, 1)),
  ((1, 1), (2, 1), (9, 1), (11, -1), (14, -1)),
  ((3, 1), (2, -1), (10, 1), (12, -1), (15, 1)),
  ((4, 1), (0, -1), (3, -1), (11, -1), (13, 1)),
  ((1, 1), (4, -1), (5, -1), (12, -1), (14, -1)),
  ((2, 1), (5, -1), (6, -1), (13, 1), (15, -1)),
  ((0, 1), (3, -1), (6, 1), (7, -1), (14, 1)),
  ((8, 1), (1, -1), (4, -1), (7, -1), (15, 1)),
  ((8, 1), (0, -1), (2, -1), (5, -1), (9, 1)),
  ((1, 1), (3, 1), (6, -1), (9, -1), (10, 1)),
  ((2, 1), (4, 1), (7, 1), (10, 1), (11, 1)),
  ((3, 1), (5, -1), (8, 1), (11, -1), (12, -1)),
  ((12, 1), (4, -1), (6, -1), (9, -1), (13, 1)),
]

# word bits, s0..s3 rotations, r1..r7 rotations, K multiplier, struct word letter

_SMALL = (32, ((4, 19), (8, 23), (12, 25), (15, 29)), (3, 7, 13, 16, 19, 23, 27), 0x05555555, "I")
_BIG   = (64, ((4, 37), (13, 43), (19, 53), (28, 59)), (5, 11, 27, 32, 37, 43, 53), 0x0555555555555555, "Q")

_IV224 = [0x00010203 + 0x04040404 * i for i in range(16)]
_IV256 = [0x40414243 + 0x04040404 * i for i in range(16)]
_IV384 = [0x0001020304050607 + 0x0808080808080808 * i for i in range(16)]
_IV512 = [0x8081828384858687 + 0x0808080808080808 * i for i in range(16)]

_FINAL_S = [0xaaaaaaa0 + i for i in range(16)]
_FINAL_B = [0xaaaaaaaaaaaaaaa0 + i for i in range(16)]


def _compress(p, h, block):
  w, srot, rrot, kmul, fmt = p

  mask = (1 << w) - 1

  def rol(x, n):
    v = ((x << n) | (x >> (w - n))) & mask

    return v

  # s0..s3 shift left by 3, 2, 1, 2 and right by 1, 1, 2, 2, s4 and s5 are plain

  sl = (3, 2, 1, 2)
  sr = (1, 1, 2, 2)

  def s(i, x):
    if i >= 4:
      v = (x >> (i - 3)) ^ x

      return v

    a, b = srot[i]

    v = (x >> sr[i]) ^ ((x << sl[i]) & mask) ^ rol(x, a) ^ rol(x, b)

    return v

  m = struct.unpack("<16" + fmt, block)

  mh = [m[i] ^ h[i] for i in range(16)]

  q = [0] * 32

  for i in range(16):
    acc = 0

    for j, sign in _W[i]:
      acc += sign * mh[j]

    q[i] = (s(i % 5, acc & mask) + h[(i + 1) % 16]) & mask

  for i in range(16, 32):
    j = i - 16

    a0 = (j + 0) % 16
    a3 = (j + 3) % 16
    a10 = (j + 10) % 16

    add = ((rol(m[a0], a0 + 1) + rol(m[a3], a3 + 1) - rol(m[a10], a10 + 1) + i * kmul) & mask) ^ h[(j + 7) % 16]

    acc = add

    if i >= 18:
      for k in range(14):
        if (k % 2) == 1:
          acc += rol(q[j + k], rrot[k // 2])
        else:
          acc += q[j + k]

      acc += s(4, q[j + 14]) + s(5, q[j + 15])
    else:
      for k in range(16):
        acc += s((1, 2, 3, 0)[k % 4], q[j + k])

    q[i] = acc & mask

  xl = 0

  for i in range(16, 24): xl ^= q[i]

  xh = xl

  for i in range(24, 32): xh ^= q[i]

  d = [0] * 16

  d[0] = (((xh << 5) & mask) ^ (q[16] >> 5) ^ m[0]) + (xl ^ q[24] ^ q[0])
  d[1] = ((xh >> 7) ^ ((q[17] << 8) & mask) ^ m[1]) + (xl ^ q[25] ^ q[1])
  d[2] = ((xh >> 5) ^ ((q[18] << 5) & mask) ^ m[2]) + (xl ^ q[26] ^ q[2])
  d[3] = ((xh >> 1) ^ ((q[19] << 5) & mask) ^ m[3]) + (xl ^ q[27] ^ q[3])
  d[4] = ((xh >> 3) ^ ((q[20] << 0) & mask) ^ m[4]) + (xl ^ q[28] ^ q[4])
  d[5] = (((xh << 6) & mask) ^ (q[21] >> 6) ^ m[5]) + (xl ^ q[29] ^ q[5])
  d[6] = ((xh >> 4) ^ ((q[22] << 6) & mask) ^ m[6]) + (xl ^ q[30] ^ q[6])
  d[7] = ((xh >> 11) ^ ((q[23] << 2) & mask) ^ m[7]) + (xl ^ q[31] ^ q[7])

  for i in range(8): d[i] &= mask

  d[8]  = rol(d[4], 9) + (xh ^ q[24] ^ m[8]) + (((xl << 8) & mask) ^ q[23] ^ q[8])
  d[9]  = rol(d[5], 10) + (xh ^ q[25] ^ m[9]) + ((xl >> 6) ^ q[16] ^ q[9])
  d[10] = rol(d[6], 11) + (xh ^ q[26] ^ m[10]) + (((xl << 6) & mask) ^ q[17] ^ q[10])
  d[11] = rol(d[7], 12) + (xh ^ q[27] ^ m[11]) + (((xl << 4) & mask) ^ q[18] ^ q[11])
  d[12] = rol(d[0], 13) + (xh ^ q[28] ^ m[12]) + ((xl >> 3) ^ q[19] ^ q[12])
  d[13] = rol(d[1], 14) + (xh ^ q[29] ^ m[13]) + ((xl >> 4) ^ q[20] ^ q[13])
  d[14] = rol(d[2], 15) + (xh ^ q[30] ^ m[14]) + ((xl >> 7) ^ q[21] ^ q[14])
  d[15] = rol(d[3], 16) + (xh ^ q[31] ^ m[15]) + ((xl >> 2) ^ q[22] ^ q[15])

  for i in range(8, 16): d[i] &= mask

  return d


def _bmw(p, iv, final, data, out_words):
  w = p[0]

  bs = w * 2

  fmt = "<16" + p[4]

  msg = data + b"\x80"
  msg += b"\x00" * ((bs - 8 - len(msg)) % bs)
  msg += struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff)

  h = iv[:]

  for off in range(0, len(msg), bs):
    h = _compress(p, h, msg[off:off + bs])

  # one more compression of the chaining value under a constant key

  h = _compress(p, final, struct.pack(fmt, *h))

  out = struct.pack("<%d%s" % (out_words, p[4]), *h[16 - out_words:])

  return out


def bmw224(data: bytes) -> bytes:
  return _bmw(_SMALL, _IV224, _FINAL_S, data, 7)


def bmw256(data: bytes) -> bytes:
  return _bmw(_SMALL, _IV256, _FINAL_S, data, 8)


def bmw384(data: bytes) -> bytes:
  return _bmw(_BIG, _IV384, _FINAL_B, data, 6)


def bmw512(data: bytes) -> bytes:
  return _bmw(_BIG, _IV512, _FINAL_B, data, 8)
