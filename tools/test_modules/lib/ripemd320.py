#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# RIPEMD-320, for modes 33600, 33650 and 33660. Neither hashlib nor pycryptodome carries it, so this
# is a small self contained implementation of the reference algorithm.

import struct

_R = 0xffffffff


def _rol(x, n):
  return ((x << n) | (x >> (32 - n))) & _R


_RL = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]

_RR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]

_SL = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]

_SR = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

_KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
_KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]


def _f(j, x, y, z):
  if j < 16:
    return x ^ y ^ z
  if j < 32:
    return (x & y) | (~x & z)
  if j < 48:
    return (x | ~y) ^ z
  if j < 64:
    return (x & z) | (y & ~z)
  return x ^ (y | ~z)


def ripemd320(data):
  h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
       0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f]

  msg = data + b"\x80"
  msg += b"\x00" * ((56 - len(msg)) % 64)
  msg += struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff)

  for off in range(0, len(msg), 64):
    x = list(struct.unpack("<16I", msg[off:off + 64]))

    al, bl, cl, dl, el = h[0], h[1], h[2], h[3], h[4]
    ar, br, cr, dr, er = h[5], h[6], h[7], h[8], h[9]

    for j in range(80):
      t = (_rol((al + _f(j, bl, cl, dl) + x[_RL[j]] + _KL[j // 16]) & _R, _SL[j]) + el) & _R
      al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t

      t = (_rol((ar + _f(79 - j, br, cr, dr) + x[_RR[j]] + _KR[j // 16]) & _R, _SR[j]) + er) & _R
      ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t

      if j == 15:
        bl, br = br, bl
      elif j == 31:
        dl, dr = dr, dl
      elif j == 47:
        al, ar = ar, al
      elif j == 63:
        cl, cr = cr, cl
      elif j == 79:
        el, er = er, el

    h = [(h[0] + al) & _R, (h[1] + bl) & _R, (h[2] + cl) & _R, (h[3] + dl) & _R, (h[4] + el) & _R,
         (h[5] + ar) & _R, (h[6] + br) & _R, (h[7] + cr) & _R, (h[8] + dr) & _R, (h[9] + er) & _R]

  return struct.pack("<10I", *h)


def ripemd320_hex(data):
  return ripemd320(data).hex()


def hmac_ripemd320_hex(key, msg):
  # HMAC over RIPEMD-320, block size 64

  if len(key) > 64:
    key = ripemd320(key)

  key = key + b"\x00" * (64 - len(key))

  ipad = bytes(b ^ 0x36 for b in key)
  opad = bytes(b ^ 0x5c for b in key)

  return ripemd320(opad + ripemd320(ipad + msg)).hex()
