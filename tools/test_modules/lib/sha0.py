#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# SHA-0, the 1993 FIPS 180 hash that SHA-1 replaced. It is SHA-1 without the 1 bit rotation in
# the message schedule. Neither hashlib nor pycryptodome carries it.

import struct

_R = 0xffffffff


def _rol(x: int, n: int) -> int:
  return ((x << n) | (x >> (32 - n))) & _R


def sha0(data: bytes) -> bytes:
  h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

  msg = data + b"\x80"
  msg += b"\x00" * ((56 - len(msg)) % 64)
  msg += struct.pack(">Q", (len(data) * 8) & 0xffffffffffffffff)

  for off in range(0, len(msg), 64):
    w = list(struct.unpack(">16I", msg[off:off + 64]))

    for i in range(16, 80): w.append(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16])

    a, b, c, d, e = h

    for i in range(80):
      if i >= 60:
        f = b ^ c ^ d
        k = 0xca62c1d6
      elif i >= 40:
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      elif i >= 20:
        f = b ^ c ^ d
        k = 0x6ed9eba1
      else:
        f = (b & c) | (~b & d)
        k = 0x5a827999

      t = (_rol(a, 5) + f + e + k + w[i]) & _R
      a, b, c, d, e = t, a, _rol(b, 30), c, d

    h = [(h[0] + a) & _R, (h[1] + b) & _R, (h[2] + c) & _R, (h[3] + d) & _R, (h[4] + e) & _R]

  return struct.pack(">5I", *h)
