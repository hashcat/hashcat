#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# RadioGatun[32] and RadioGatun[64], following sphlib's radiogatun.c. Neither hashlib nor
# pycryptodome carries them, so this is a small self contained implementation.

import struct


def _mill(a: list, w: int, m: int) -> list:
  t = [a[i] ^ (a[(i + 1) % 19] | (~a[(i + 2) % 19] & m)) for i in range(19)]

  # rotate right by i * (i + 1) / 2, taken from word 7 * i

  r = []

  for i in range(19):
    v = t[(7 * i) % 19]
    n = ((i * (i + 1)) >> 1) % w

    if n > 0: v = ((v >> n) | (v << (w - n))) & m

    r.append(v)

  out = [r[i] ^ r[(i + 1) % 19] ^ r[(i + 4) % 19] for i in range(19)]

  out[0] ^= 1

  return out


def _round(a: list, b: list, j: int, w: int, m: int) -> list:
  # the belt is 13 stages of 3 words, j is the stage pointer that moves down one per round

  for k in range(1, 13): b[(j + k) % 13][(k - 1) % 3] ^= a[k]

  a = _mill(a, w, m)

  bj = b[j]

  a[13] ^= bj[0]
  a[14] ^= bj[1]
  a[15] ^= bj[2]

  return a


def _radiogatun(data: bytes, w: int) -> bytes:
  m   = (1 << w) - 1
  wb  = w // 8
  fmt = "<3I" if w == 32 else "<3Q"

  a = [0] * 19
  b = [[0] * 3 for _ in range(13)]
  j = 12

  # pad with 0x01 and zeros to a multiple of 3 words

  msg = data + b"\x01"
  msg += b"\x00" * ((3 * wb - len(msg)) % (3 * wb))

  for off in range(0, len(msg), 3 * wb):
    p0, p1, p2 = struct.unpack(fmt, msg[off:off + 3 * wb])

    bi = b[(j + 1) % 13]

    bi[0] ^= p0
    bi[1] ^= p1
    bi[2] ^= p2

    a[16] ^= p0
    a[17] ^= p1
    a[18] ^= p2

    a = _round(a, b, j, w, m)
    j = (j - 1) % 13

  # 16 blank rounds, then a round before every 2 output words

  for _ in range(16):
    a = _round(a, b, j, w, m)
    j = (j - 1) % 13

  out = "<2I" if w == 32 else "<2Q"

  digest = b""

  while len(digest) < 32:
    a = _round(a, b, j, w, m)
    j = (j - 1) % 13

    digest += struct.pack(out, a[1], a[2])

  return digest


def radiogatun32(data: bytes) -> bytes:
  # the first 16 bytes of the 32 byte RadioGatun[32] digest

  digest = _radiogatun(data, 32)[:16]

  return digest


def radiogatun64(data: bytes) -> bytes:
  digest = _radiogatun(data, 64)

  return digest
