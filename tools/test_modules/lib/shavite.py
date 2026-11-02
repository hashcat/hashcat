#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# SHAvite-3 224/256/384/512, the round 2 tweaked SHA-3 candidate built on AES rounds, following the
# specification. Neither hashlib nor pycryptodome carries it, so this is a self contained version.

import struct

_M32 = 0xffffffff

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

_IV224 = [
  0x6774f31c, 0x990ae210, 0xc87d4274, 0xc9546371, 0x62b2aea8, 0x4b5801d8, 0x1b702860, 0x842f3017,
]

_IV256 = [
  0x49bb3e47, 0x2674860d, 0xa8b392ac, 0x021ac4e6, 0x409283cf, 0x620e5d86, 0x6d929dcb, 0x96cc2a8b,
]

_IV384 = [
  0x83df1545, 0xf9aaec13, 0xf4803cb0, 0x11fe1f47, 0xda6cd269, 0x4f53fcd7, 0x950529a2, 0x97908147,
  0xb0a4d7af, 0x2b9132bf, 0x226e607d, 0x3c0f8d7c, 0x487b3f0f, 0x04363e22, 0x0155c99c, 0xec2e20d3,
]

_IV512 = [
  0x72fccdd8, 0x79ca4727, 0x128a077b, 0x40d55aec, 0xd1901a06, 0x430ae307, 0xb29f5cd1, 0xdf07fbfc,
  0x8e45d73d, 0x681ab538, 0xbde86578, 0xdd577e47, 0xe275eade, 0x502d9fcd, 0xb9357178, 0x022a4b9a,
]


def _make_tables():
  t0 = []

  for x in range(256):
    s1 = _SBOX[x]
    s2 = ((s1 << 1) ^ (0x11b if s1 >= 0x80 else 0)) & 0xff
    s3 = s2 ^ s1

    t0.append(s2 | (s1 << 8) | (s1 << 16) | (s3 << 24))

  t1 = [((w << 8) | (w >> 24)) & _M32 for w in t0]
  t2 = [((w << 8) | (w >> 24)) & _M32 for w in t1]
  t3 = [((w << 8) | (w >> 24)) & _M32 for w in t2]

  return t0, t1, t2, t3


_T0, _T1, _T2, _T3 = _make_tables()


# one unkeyed AES round on 4 little-endian column words

def _aes(x0, x1, x2, x3):
  t0 = _T0
  t1 = _T1
  t2 = _T2
  t3 = _T3

  y0 = t0[x0 & 0xff] ^ t1[(x1 >> 8) & 0xff] ^ t2[(x2 >> 16) & 0xff] ^ t3[x3 >> 24]
  y1 = t0[x1 & 0xff] ^ t1[(x2 >> 8) & 0xff] ^ t2[(x3 >> 16) & 0xff] ^ t3[x0 >> 24]
  y2 = t0[x2 & 0xff] ^ t1[(x3 >> 8) & 0xff] ^ t2[(x0 >> 16) & 0xff] ^ t3[x1 >> 24]
  y3 = t0[x3 & 0xff] ^ t1[(x0 >> 8) & 0xff] ^ t2[(x1 >> 16) & 0xff] ^ t3[x2 >> 24]

  return y0, y1, y2, y3


def _c256(h, block, count):
  c0 = (count >>  0) & _M32
  c1 = (count >> 32) & _M32

  rk = list(struct.unpack("<16I", block))

  u = 16

  for r in range(4):
    for s in range(4):
      x0, x1, x2, x3 = _aes(rk[u - 15], rk[u - 14], rk[u - 13], rk[u - 16])

      rk.append(x0 ^ rk[u - 4])
      rk.append(x1 ^ rk[u - 3])
      rk.append(x2 ^ rk[u - 2])
      rk.append(x3 ^ rk[u - 1])

      if u == 16:
        rk[16] ^= c0
        rk[17] ^= c1 ^ _M32
      elif u == 56:
        rk[57] ^= c1
        rk[58] ^= c0 ^ _M32
      elif u == 84:
        rk[86] ^= c1
        rk[87] ^= c0 ^ _M32
      elif u == 124:
        rk[124] ^= c0
        rk[127] ^= c1 ^ _M32

      u += 4

    for s in range(16):
      rk.append(rk[u - 16] ^ rk[u - 3])

      u += 1

  p = list(h)

  u = 0

  for r in range(6):
    for half in (0, 4):
      src = 4 - half

      x0, x1, x2, x3 = _aes(p[src + 0] ^ rk[u + 0], p[src + 1] ^ rk[u + 1], p[src + 2] ^ rk[u + 2], p[src + 3] ^ rk[u + 3])
      x0, x1, x2, x3 = _aes(x0 ^ rk[u + 4], x1 ^ rk[u + 5], x2 ^ rk[u + 6], x3 ^ rk[u + 7])
      x0, x1, x2, x3 = _aes(x0 ^ rk[u + 8], x1 ^ rk[u + 9], x2 ^ rk[u + 10], x3 ^ rk[u + 11])

      p[half + 0] ^= x0
      p[half + 1] ^= x1
      p[half + 2] ^= x2
      p[half + 3] ^= x3

      u += 12

  out = [h[i] ^ p[i] for i in range(8)]

  return out


def _c512(h, block, count):
  c0 = (count >>  0) & _M32
  c1 = (count >> 32) & _M32
  c2 = (count >> 64) & _M32
  c3 = (count >> 96) & _M32

  rk = list(struct.unpack("<32I", block))

  u = 32

  while True:
    for s in range(8):
      x0, x1, x2, x3 = _aes(rk[u - 31], rk[u - 30], rk[u - 29], rk[u - 32])

      rk.append(x0 ^ rk[u - 4])
      rk.append(x1 ^ rk[u - 3])
      rk.append(x2 ^ rk[u - 2])
      rk.append(x3 ^ rk[u - 1])

      if u == 32:
        rk[32] ^= c0
        rk[33] ^= c1
        rk[34] ^= c2
        rk[35] ^= c3 ^ _M32
      elif u == 164:
        rk[164] ^= c3
        rk[165] ^= c2
        rk[166] ^= c1
        rk[167] ^= c0 ^ _M32
      elif u == 316:
        rk[316] ^= c2
        rk[317] ^= c3
        rk[318] ^= c0
        rk[319] ^= c1 ^ _M32
      elif u == 440:
        rk[440] ^= c1
        rk[441] ^= c0
        rk[442] ^= c3
        rk[443] ^= c2 ^ _M32

      u += 4

    if u == 448: break

    for s in range(32):
      rk.append(rk[u - 32] ^ rk[u - 7])

      u += 1

  p = list(h)

  u = 0

  for r in range(14):
    for left, right in ((0, 4), (8, 12)):
      x0 = p[right + 0] ^ rk[u + 0]
      x1 = p[right + 1] ^ rk[u + 1]
      x2 = p[right + 2] ^ rk[u + 2]
      x3 = p[right + 3] ^ rk[u + 3]

      for k in range(4, 16, 4):
        x0, x1, x2, x3 = _aes(x0, x1, x2, x3)

        x0 ^= rk[u + k + 0]
        x1 ^= rk[u + k + 1]
        x2 ^= rk[u + k + 2]
        x3 ^= rk[u + k + 3]

      x0, x1, x2, x3 = _aes(x0, x1, x2, x3)

      p[left + 0] ^= x0
      p[left + 1] ^= x1
      p[left + 2] ^= x2
      p[left + 3] ^= x3

      u += 16

    # rotate the 4 lanes of 128 bits: (p0, p4, p8, pC) becomes (pC, p0, p4, p8)

    p = p[12:16] + p[0:12]

  out = [h[i] ^ p[i] for i in range(16)]

  return out


def _shavite(data, iv, out_len):
  big = out_len > 32

  bs    = 128 if big else 64
  comp  = _c512 if big else _c256
  cbits = 128 if big else 64
  cpos  = bs - 2 - cbits // 8

  h = list(iv)

  full = len(data) - (len(data) % bs)

  count = 0

  for off in range(0, full, bs):
    count += bs * 8

    h = comp(h, data[off:off + bs], count)

  tail = data[full:]

  count += len(tail) * 8

  total = count

  # a final block holding only the padding bit is processed with a counter of 0

  if len(tail) == 0: count = 0

  buf = bytearray(tail + b"\x80" + bytes(bs - len(tail) - 1))

  if len(tail) >= cpos:
    h = comp(h, bytes(buf), count)

    count = 0

    buf = bytearray(bs)

  buf[cpos:cpos + cbits // 8] = (total & ((1 << cbits) - 1)).to_bytes(cbits // 8, "little")
  buf[bs - 2:bs - 0] = struct.pack("<H", out_len * 8)

  h = comp(h, bytes(buf), count)

  out = struct.pack("<%dI" % len(h), *h)

  return out[:out_len]


def shavite224(data: bytes) -> bytes:
  return _shavite(bytes(data), _IV224, 28)


def shavite256(data: bytes) -> bytes:
  return _shavite(bytes(data), _IV256, 32)


def shavite384(data: bytes) -> bytes:
  return _shavite(bytes(data), _IV384, 48)


def shavite512(data: bytes) -> bytes:
  return _shavite(bytes(data), _IV512, 64)
