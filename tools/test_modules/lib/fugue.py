#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Fugue-224/256/384/512, the SHA-3 candidate. Neither hashlib nor pycryptodome carries it, so this
# is a small self contained implementation of the reference algorithm.

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
  0xf4c9120d, 0x6286f757, 0xee39e01c, 0xe074e3cb, 0xa1127c62, 0x9a43d215, 0xbd8d679a,
]

_IV256 = [
  0xe952bdde, 0x6671135f, 0xe0d4f668, 0xd2b0b594, 0xf96c621d, 0xfbf929de, 0x9149e899, 0x34f8c248,
]

_IV384 = [
  0xaa61ec0d, 0x31252e1f, 0xa01db4c7, 0x00600985, 0x215ef44a, 0x741b5e9c,
  0xfa693e9a, 0x473eb040, 0xe502ae8a, 0xa99c25e0, 0xbc95517c, 0x5c1095a1,
]

_IV512 = [
  0x8807a57e, 0xe616af75, 0xc5d3e4db, 0xac9ab027, 0xd915f117, 0xb6eecc54, 0x06e8020b, 0x4a92efd1,
  0xaac6e2c9, 0xddb21398, 0xcae65838, 0x437f203f, 0x25ea78e7, 0x951fddd6, 0xda6ed11d, 0xe13e3567,
]


def _gmul(a, b):
  r = 0

  while b > 0:
    if (b & 1) == 1: r ^= a

    a <<= 1

    if (a & 0x100) != 0: a ^= 0x11b

    b >>= 1

  return r


# the S-box byte times the column (1, 1, 7, 4) of the super-mix matrix, big-endian

def _make_tables():
  t0 = []

  for x in range(256):
    s = _SBOX[x]

    t0.append((s << 24) | (s << 16) | (_gmul(s, 7) << 8) | _gmul(s, 4))

  t1 = [((w >>  8) | (w << 24)) & _M32 for w in t0]
  t2 = [((w >> 16) | (w << 16)) & _M32 for w in t0]
  t3 = [((w >> 24) | (w <<  8)) & _M32 for w in t0]

  return t0, t1, t2, t3


_MT0, _MT1, _MT2, _MT3 = _make_tables()


def _smix(s):
  m0 = _MT0
  m1 = _MT1
  m2 = _MT2
  m3 = _MT3

  x0 = s[0]
  x1 = s[1]
  x2 = s[2]
  x3 = s[3]

  a0 = m0[x0 >> 24]
  a1 = m1[(x0 >> 16) & 0xff]
  a2 = m2[(x0 >>  8) & 0xff]
  a3 = m3[(x0 >>  0) & 0xff]

  b0 = m0[x1 >> 24]
  b1 = m1[(x1 >> 16) & 0xff]
  b2 = m2[(x1 >>  8) & 0xff]
  b3 = m3[(x1 >>  0) & 0xff]

  d0 = m0[x2 >> 24]
  d1 = m1[(x2 >> 16) & 0xff]
  d2 = m2[(x2 >>  8) & 0xff]
  d3 = m3[(x2 >>  0) & 0xff]

  e0 = m0[x3 >> 24]
  e1 = m1[(x3 >> 16) & 0xff]
  e2 = m2[(x3 >>  8) & 0xff]
  e3 = m3[(x3 >>  0) & 0xff]

  # column mix of each input word, and the row sums of the cross terms

  c0 = a0 ^ a1 ^ a2 ^ a3
  c1 = b0 ^ b1 ^ b2 ^ b3
  c2 = d0 ^ d1 ^ d2 ^ d3
  c3 = e0 ^ e1 ^ e2 ^ e3

  r0 = b0 ^ d0 ^ e0
  r1 = a1 ^ d1 ^ e1
  r2 = a2 ^ b2 ^ e2
  r3 = a3 ^ b3 ^ d3

  s[0] = ((c0 ^ r0) & 0xff000000) | ((c1 ^ r1) & 0x00ff0000) | ((c2 ^ r2) & 0x0000ff00) | ((c3 ^ r3) & 0x000000ff)
  s[1] = ((c1 ^ (r0 << 8)) & 0xff000000) | ((c2 ^ (r1 << 8)) & 0x00ff0000) | ((c3 ^ (r2 << 8)) & 0x0000ff00) | ((c0 ^ (r3 >> 24)) & 0x000000ff)
  s[2] = ((c2 ^ (r0 << 16)) & 0xff000000) | ((c3 ^ (r1 << 16)) & 0x00ff0000) | ((c0 ^ (r2 >> 16)) & 0x0000ff00) | ((c1 ^ (r3 >> 16)) & 0x000000ff)
  s[3] = ((c3 ^ (r0 << 24)) & 0xff000000) | ((c0 ^ (r1 >> 8)) & 0x00ff0000) | ((c1 ^ (r2 >> 8)) & 0x0000ff00) | ((c2 ^ (r3 >> 8)) & 0x000000ff)


def _cmix(s, k):
  s[0] ^= s[4]
  s[1] ^= s[5]
  s[2] ^= s[6]

  s[k + 0] ^= s[4]
  s[k + 1] ^= s[5]
  s[k + 2] ^= s[6]


def _ror(s, n):
  r = s[-n:] + s[:-n]

  return r


def _round(s, w, lanes):
  if lanes == 2:
    s[10] ^= s[0]
    s[0]   = w
    s[8]  ^= s[0]
    s[1]  ^= s[24]

    k = 15
  elif lanes == 3:
    s[16] ^= s[0]
    s[0]   = w
    s[8]  ^= s[0]
    s[1]  ^= s[27]
    s[4]  ^= s[30]

    k = 18
  else:
    s[22] ^= s[0]
    s[0]   = w
    s[8]  ^= s[0]
    s[1]  ^= s[24]
    s[4]  ^= s[27]
    s[7]  ^= s[30]

    k = 18

  for _ in range(lanes):
    s = _ror(s, 3)

    _cmix(s, k)
    _smix(s)

  return s


# the final rounds: (xor positions, rotation) steps of the inner loop and the output words

_FINAL = {
  2: (10, 15, [([4, 15], 15), ([4, 16], 14)], [1, 2, 3, 4, 15, 16, 17, 18]),
  3: (18, 18, [([4, 12, 24], 12), ([4, 13, 24], 12), ([4, 13, 25], 11)], [1, 2, 3, 4, 12, 13, 14, 15, 24, 25, 26, 27]),
  4: (32, 18, [([4, 9, 18, 27], 9), ([4, 10, 18, 27], 9), ([4, 10, 19, 27], 9), ([4, 10, 19, 28], 8)], [1, 2, 3, 4, 9, 10, 11, 12, 18, 19, 20, 21, 27, 28, 29, 30]),
}


def _fugue(data, iv, lanes, out_len):
  size = 30 if lanes == 2 else 36

  s = [0] * (size - len(iv)) + list(iv)

  # zero pad to whole words, then the 64-bit big-endian bit length

  msg = data + bytes((4 - (len(data) % 4)) % 4) + struct.pack(">Q", len(data) * 8)

  for w in struct.unpack(">%dI" % (len(msg) // 4), msg):
    s = _round(s, w, lanes)

  g1, k, steps, outw = _FINAL[lanes]

  for _ in range(g1):
    s = _ror(s, 3)

    _cmix(s, k)
    _smix(s)

  for _ in range(13):
    for pos, rot in steps:
      for p in pos: s[p] ^= s[0]

      s = _ror(s, rot)

      _smix(s)

  for p in steps[0][0]: s[p] ^= s[0]

  out = struct.pack(">%dI" % len(outw), *[s[i] for i in outw])

  return out[:out_len]


def fugue224(data: bytes) -> bytes:
  return _fugue(bytes(data), _IV224, 2, 28)


def fugue256(data: bytes) -> bytes:
  return _fugue(bytes(data), _IV256, 2, 32)


def fugue384(data: bytes) -> bytes:
  return _fugue(bytes(data), _IV384, 3, 48)


def fugue512(data: bytes) -> bytes:
  return _fugue(bytes(data), _IV512, 4, 64)
