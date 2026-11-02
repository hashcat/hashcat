#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# ECHO-224/256/384/512, the SHA-3 candidate built on AES rounds. Neither hashlib nor pycryptodome
# carries it, so this is a small self contained implementation of the reference algorithm.

import struct

_M32  = 0xffffffff
_M128 = (1 << 128) - 1

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


# one AES round on 4 little-endian column words, then the key XOR

def _aes_round(x0, x1, x2, x3, k0, k1, k2, k3):
  t0 = _T0
  t1 = _T1
  t2 = _T2
  t3 = _T3

  y0 = t0[x0 & 0xff] ^ t1[(x1 >> 8) & 0xff] ^ t2[(x2 >> 16) & 0xff] ^ t3[x3 >> 24] ^ k0
  y1 = t0[x1 & 0xff] ^ t1[(x2 >> 8) & 0xff] ^ t2[(x3 >> 16) & 0xff] ^ t3[x0 >> 24] ^ k1
  y2 = t0[x2 & 0xff] ^ t1[(x3 >> 8) & 0xff] ^ t2[(x0 >> 16) & 0xff] ^ t3[x1 >> 24] ^ k2
  y3 = t0[x3 & 0xff] ^ t1[(x0 >> 8) & 0xff] ^ t2[(x1 >> 16) & 0xff] ^ t3[x2 >> 24] ^ k3

  return y0, y1, y2, y3


def _xtime(x):
  r = (((x & 0x80808080) >> 7) * 27) ^ ((x & 0x7f7f7f7f) << 1)

  return r


def _compress(v, block, counter, rounds):
  nv = len(v) // 4

  w = [tuple(v[4 * i:4 * i + 4]) for i in range(nv)]

  m = struct.unpack("<%dI" % (len(block) // 4), block)

  for i in range(16 - nv):
    w.append(tuple(m[4 * i:4 * i + 4]))

  k = counter

  for _ in range(rounds):

    # BIG.SubWords: 2 AES rounds per 128-bit word, the first keyed with the counter

    for n in range(16):
      x0, x1, x2, x3 = w[n]

      y0, y1, y2, y3 = _aes_round(x0, x1, x2, x3, k & _M32, (k >> 32) & _M32, (k >> 64) & _M32, k >> 96)

      w[n] = _aes_round(y0, y1, y2, y3, 0, 0, 0, 0)

      k = (k + 1) & _M128

    # BIG.ShiftRows

    w = [w[(n + 4 * (n % 4)) % 16] for n in range(16)]

    # BIG.MixColumns

    for c in range(0, 16, 4):
      wa = w[c + 0]
      wb = w[c + 1]
      wc = w[c + 2]
      wd = w[c + 3]

      ra = []
      rb = []
      rc = []
      rd = []

      for n in range(4):
        a = wa[n]
        b = wb[n]
        cc = wc[n]
        d = wd[n]

        ab = a ^ b
        bc = b ^ cc
        cd = cc ^ d

        abx = _xtime(ab)
        bcx = _xtime(bc)
        cdx = _xtime(cd)

        ra.append(abx ^ bc ^ d)
        rb.append(bcx ^ a ^ cd)
        rc.append(cdx ^ ab ^ d)
        rd.append(abx ^ bcx ^ cdx ^ ab ^ cc)

      w[c + 0] = ra
      w[c + 1] = rb
      w[c + 2] = rc
      w[c + 3] = rd

  flat = [x for col in w for x in col]

  out = []

  for u in range(len(v)):
    x = v[u] ^ m[u] ^ flat[u] ^ flat[u + len(v)]

    if nv == 4: x ^= m[u + 16] ^ m[u + 32] ^ flat[u + 32] ^ flat[u + 48]

    out.append(x)

  return out


def _echo(data, out_len):
  big = out_len > 32

  bs     = 128 if big else 192
  rounds = 10 if big else 8
  nv     = 8 if big else 4

  v = []

  for _ in range(nv): v.extend([out_len * 8, 0, 0, 0])

  counter = 0

  full = len(data) - (len(data) % bs)

  for off in range(0, full, bs):
    counter = (counter + bs * 8) & _M128

    v = _compress(v, data[off:off + bs], counter, rounds)

  tail = data[full:]

  elen = len(tail) * 8

  counter = (counter + elen) & _M128

  total = counter

  # a final block holding only the padding bit is processed with a counter of 0

  if elen == 0: counter = 0

  buf = bytearray(tail + b"\x80" + bytes(bs - len(tail) - 1))

  if len(tail) + 1 > bs - 18:
    v = _compress(v, bytes(buf), counter, rounds)

    counter = 0

    buf = bytearray(bs)

  buf[bs - 18:bs - 16] = struct.pack("<H", out_len * 8)
  buf[bs - 16:bs - 0] = total.to_bytes(16, "little")

  v = _compress(v, bytes(buf), counter, rounds)

  out = struct.pack("<%dI" % len(v), *v)

  return out[:out_len]


def echo224(data: bytes) -> bytes:
  return _echo(bytes(data), 28)


def echo256(data: bytes) -> bytes:
  return _echo(bytes(data), 32)


def echo384(data: bytes) -> bytes:
  return _echo(bytes(data), 48)


def echo512(data: bytes) -> bytes:
  return _echo(bytes(data), 64)
