#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# PANAMA used as a hash, little endian words as in sphlib's panama.c. Neither hashlib nor
# pycryptodome carries it, so this is a small self contained implementation.

import struct

_R = 0xffffffff

# pi: state word i is taken from gamma word _PI_SRC[i], rotated left by _PI_ROT[i]

_PI_SRC = [(7 * i) % 17 for i in range(17)]
_PI_ROT = [((i * (i + 1)) // 2) % 32 for i in range(17)]


def _rol(x: int, n: int) -> int:
  if n == 0: return x

  r = ((x << n) | (x >> (32 - n))) & _R

  return r


def _step(a: list, buf: list, ptr: int, inp1: list, inp2: list) -> int:
  # one iteration: belt update with inp1, then gamma, pi, theta and sigma with inp2. Returns the
  # new belt pointer, a is updated in place

  ptr24 = (ptr - 8) & 31
  ptr31 = (ptr - 1) & 31

  b24 = buf[ptr24]
  b31 = buf[ptr31]

  for j in range(8):
    b24[j] ^= b31[(j + 2) & 7]
    b31[(j + 2) & 7] ^= inp1[(j + 2) & 7]

  g = [a[i] ^ (a[(i + 1) % 17] | (~a[(i + 2) % 17] & _R)) for i in range(17)]
  p = [_rol(g[_PI_SRC[i]], _PI_ROT[i]) for i in range(17)]
  t = [p[i] ^ p[(i + 1) % 17] ^ p[(i + 4) % 17] for i in range(17)]

  b16 = buf[ptr ^ 16]

  a[0] = t[0] ^ 1

  for j in range(8):
    a[1 + j] = t[1 + j] ^ inp2[j]
    a[9 + j] = t[9 + j] ^ b16[j]

  return ptr31


def panama(data: bytes) -> bytes:
  a   = [0] * 17
  buf = [[0] * 8 for _ in range(32)]
  ptr = 0

  # pad with 0x01 and zeros to a multiple of 32 bytes

  msg = data + b"\x01"
  msg += b"\x00" * ((32 - len(msg)) % 32)

  for off in range(0, len(msg), 32):
    x = list(struct.unpack("<8I", msg[off:off + 32]))

    ptr = _step(a, buf, ptr, x, x)

  # 32 blank pulls: the belt takes the state words 1..8, sigma takes belt stage ptr + 4

  for _ in range(32):
    inp2 = list(buf[(ptr + 4) & 31])

    ptr = _step(a, buf, ptr, a[1:9], inp2)

  digest = struct.pack("<8I", *a[9:17])

  return digest
