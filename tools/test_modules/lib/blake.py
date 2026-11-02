#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# BLAKE-224, BLAKE-256, BLAKE-384 and BLAKE-512, the SHA-3 round 3 finalist (not BLAKE2). Neither
# hashlib nor pycryptodome carries it, so this is a small self contained implementation.

import struct

_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

_CS = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
]

_CB = [
  0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
  0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
  0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
  0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
]

_IV224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
_IV256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

_IV384 = [
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
  0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
]

_IV512 = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

# word bits, rounds, rotations, constants, struct word letter

_SMALL = (32, 14, (16, 12, 8, 7), _CS, "I")
_BIG   = (64, 16, (32, 25, 16, 11), _CB, "Q")

# the four column steps and the four diagonal steps of one round

_STEPS = [
  (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
  (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
]


def _compress(p, h, block, t):
  w, rounds, rot, c, fmt = p

  mask = (1 << w) - 1

  r0, r1, r2, r3 = rot

  l0 = w - r0
  l1 = w - r1
  l2 = w - r2
  l3 = w - r3

  m = struct.unpack(">16" + fmt, block)

  t0 = (t >> 0) & mask
  t1 = (t >> w) & mask

  v = h[:] + [c[0], c[1], c[2], c[3], t0 ^ c[4], t0 ^ c[5], t1 ^ c[6], t1 ^ c[7]]

  for r in range(rounds):
    s = _SIGMA[r % 10]

    for i in range(8):
      a, b, cc, d = _STEPS[i]

      x0 = s[2 * i + 0]
      x1 = s[2 * i + 1]

      va = (v[a] + v[b] + (m[x0] ^ c[x1])) & mask
      vd = v[d] ^ va
      vd = ((vd >> r0) | (vd << l0)) & mask
      vc = (v[cc] + vd) & mask
      vb = v[b] ^ vc
      vb = ((vb >> r1) | (vb << l1)) & mask

      va = (va + vb + (m[x1] ^ c[x0])) & mask
      vd = vd ^ va
      vd = ((vd >> r2) | (vd << l2)) & mask
      vc = (vc + vd) & mask
      vb = vb ^ vc
      vb = ((vb >> r3) | (vb << l3)) & mask

      v[a]  = va
      v[b]  = vb
      v[cc] = vc
      v[d]  = vd

  out = [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]

  return out


def _blake(p, iv, data, out_words, last_bit):
  w = p[0]

  bs = w * 2

  # the padded tail ends with a marker bit (set for the full width variants) and the bit length

  n = len(data)

  total = n * 8

  msg = data + b"\x80"
  msg += b"\x00" * ((bs - (w // 4) - len(msg)) % bs)

  if last_bit == True:
    msg = msg[:-1] + bytes([msg[-1] | 1])

  msg += (total % (1 << (2 * w))).to_bytes(w // 4, "big")

  h = iv[:]

  for off in range(0, len(msg), bs):
    # the counter covers message bits up to the end of this block, 0 for a block of padding only

    done = off * 8

    t = 0

    if total > done: t = min(total, done + bs * 8)

    h = _compress(p, h, msg[off:off + bs], t)

  fmt = ">%d%s" % (out_words, p[4])

  result = struct.pack(fmt, *h[:out_words])

  return result


def blake224(data: bytes) -> bytes:
  return _blake(_SMALL, _IV224, data, 7, False)


def blake256(data: bytes) -> bytes:
  return _blake(_SMALL, _IV256, data, 8, True)


def blake384(data: bytes) -> bytes:
  return _blake(_BIG, _IV384, data, 6, False)


def blake512(data: bytes) -> bytes:
  return _blake(_BIG, _IV512, data, 8, True)
