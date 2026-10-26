#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# HAVAL (Zheng, Pieprzyk and Seberry), all 15 variants: 128 to 256 bits with 3, 4 or 5 passes.
# Neither hashlib nor pycryptodome carries it, so this is a small self contained implementation.

import struct

_M = 0xffffffff


def _rotr(x: int, n: int) -> int:
  return ((x >> n) | (x << (32 - n))) & _M


def _rotl(x: int, n: int) -> int:
  return ((x << n) | (x >> (32 - n))) & _M


# The 5 boolean functions, arguments in the order x6 down to x0

def _f1(x6, x5, x4, x3, x2, x1, x0):
  return (x1 & (x0 ^ x4)) ^ (x2 & x5) ^ (x3 & x6) ^ x0


def _f2(x6, x5, x4, x3, x2, x1, x0):
  return (x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0)) ^ (x4 & (x1 ^ x5)) ^ (x3 & x5) ^ x0


def _f3(x6, x5, x4, x3, x2, x1, x0):
  return (x3 & ((x1 & x2) ^ x6 ^ x0)) ^ (x1 & x4) ^ (x2 & x5) ^ x0


def _f4(x6, x5, x4, x3, x2, x1, x0):
  return (x3 & ((x1 & x2) ^ (x4 | x6) ^ x5)) ^ (x4 & ((~x2 & x5) ^ x1 ^ x6 ^ x0)) ^ (x2 & x6) ^ x0


def _f5(x6, x5, x4, x3, x2, x1, x0):
  return (x0 & ~((x1 & x2 & x3) ^ x5)) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6)


# For each pass count, each pass: its function and the state words it reads as x6 down to x0

_PHI = {
  3: [(_f1, (1, 0, 3, 5, 6, 2, 4)),
      (_f2, (4, 2, 1, 0, 5, 3, 6)),
      (_f3, (6, 1, 2, 3, 4, 5, 0))],
  4: [(_f1, (2, 6, 1, 4, 5, 3, 0)),
      (_f2, (3, 5, 2, 0, 1, 6, 4)),
      (_f3, (1, 4, 3, 6, 0, 2, 5)),
      (_f4, (6, 4, 0, 5, 2, 1, 3))],
  5: [(_f1, (3, 4, 1, 0, 5, 2, 6)),
      (_f2, (6, 2, 1, 0, 3, 4, 5)),
      (_f3, (2, 6, 0, 4, 3, 1, 5)),
      (_f4, (1, 5, 3, 2, 0, 4, 6)),
      (_f5, (2, 5, 0, 6, 4, 3, 1))],
}

# Message word order of each pass

_ORD = [
  list(range(32)),
  [5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8, 30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27],
  [19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26, 31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2],
  [24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3, 22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13],
  [27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10, 5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15],
]

# Round constants of passes 2 to 5, the fraction digits of pi. Pass 1 adds none.

_K = [
  [0] * 32,
  [0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
   0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
   0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
   0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5],
  [0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
   0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
   0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
   0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c],
  [0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
   0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
   0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
   0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4],
  [0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
   0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
   0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
   0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4],
]

_IV = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89]


def _compress(s: list, w: tuple, passes: int) -> list:
  t = s[:]

  for p, (f, phi) in enumerate(_PHI[passes]):
    order = _ORD[p]
    k = _K[p]

    for i in range(32):
      # state word j of this step is t[(j - i) % 8], the step writes word 7

      x = [t[(j - i) & 7] for j in range(8)]

      v = f(x[phi[0]], x[phi[1]], x[phi[2]], x[phi[3]], x[phi[4]], x[phi[5]], x[phi[6]]) & _M

      t[(7 - i) & 7] = (_rotr(v, 7) + _rotr(x[7], 11) + w[order[i]] + k[i]) & _M

  out = [(s[j] + t[j]) & _M for j in range(8)]

  return out


def _fold(s: list, words: int) -> list:
  # Folds the 256 bit state down to the digest size

  s0, s1, s2, s3, s4, s5, s6, s7 = s

  if words == 8: return s

  if words == 7:
    return [s0 + ((s7 >> 27) & 0x1f), s1 + ((s7 >> 22) & 0x1f), s2 + ((s7 >> 18) & 0x0f), s3 + ((s7 >> 13) & 0x1f),
            s4 + ((s7 >>  9) & 0x0f), s5 + ((s7 >>  4) & 0x1f), s6 + ((s7 >>  0) & 0x0f)]

  if words == 6:
    return [s0 + _rotl((s6 & 0xfc000000) | (s7 & 0x0000001f), 6),
            s1 + ((s6 & 0x0000001f) | (s7 & 0x000003e0)),
            s2 + (((s6 & 0x000003e0) | (s7 & 0x0000fc00)) >>  5),
            s3 + (((s6 & 0x0000fc00) | (s7 & 0x001f0000)) >> 10),
            s4 + (((s6 & 0x001f0000) | (s7 & 0x03e00000)) >> 16),
            s5 + (((s6 & 0x03e00000) | (s7 & 0xfc000000)) >> 21)]

  if words == 5:
    return [s0 + _rotl((s5 & 0x01f80000) | (s6 & 0xfe000000) | (s7 & 0x0000003f), 13),
            s1 + _rotl((s5 & 0xfe000000) | (s6 & 0x0000003f) | (s7 & 0x00000fc0), 7),
            s2 + (((s5 & 0x0000003f) | (s6 & 0x00000fc0) | (s7 & 0x0007f000)) >>  0),
            s3 + (((s5 & 0x00000fc0) | (s6 & 0x0007f000) | (s7 & 0x01f80000)) >>  6),
            s4 + (((s5 & 0x0007f000) | (s6 & 0x01f80000) | (s7 & 0xfe000000)) >> 12)]

  return [s0 + _rotl((s7 & 0x000000ff) | (s4 & 0x0000ff00) | (s5 & 0x00ff0000) | (s6 & 0xff000000), 24),
          s1 + _rotl((s6 & 0x000000ff) | (s7 & 0x0000ff00) | (s4 & 0x00ff0000) | (s5 & 0xff000000), 16),
          s2 + _rotl((s5 & 0x000000ff) | (s6 & 0x0000ff00) | (s7 & 0x00ff0000) | (s4 & 0xff000000), 8),
          s3 + ((s4 & 0x000000ff) | (s5 & 0x0000ff00) | (s6 & 0x00ff0000) | (s7 & 0xff000000))]


def _haval(data: bytes, bits: int, passes: int) -> bytes:
  words = bits // 32

  # 0x01 ends the message, the last 10 bytes carry the version, pass count, digest size and length

  msg = data + b"\x01"
  msg += b"\x00" * ((118 - len(msg)) % 128)
  msg += bytes([0x01 | (passes << 3), (words << 3) & 0xff])
  msg += struct.pack("<Q", (len(data) * 8) & 0xffffffffffffffff)

  s = _IV[:]

  for off in range(0, len(msg), 128): s = _compress(s, struct.unpack("<32I", msg[off:off + 128]), passes)

  out = [v & _M for v in _fold(s, words)]

  return struct.pack("<%dI" % words, *out)


def hav128_3(data: bytes) -> bytes: return _haval(data, 128, 3)
def hav128_4(data: bytes) -> bytes: return _haval(data, 128, 4)
def hav128_5(data: bytes) -> bytes: return _haval(data, 128, 5)
def hav160_3(data: bytes) -> bytes: return _haval(data, 160, 3)
def hav160_4(data: bytes) -> bytes: return _haval(data, 160, 4)
def hav160_5(data: bytes) -> bytes: return _haval(data, 160, 5)
def hav192_3(data: bytes) -> bytes: return _haval(data, 192, 3)
def hav192_4(data: bytes) -> bytes: return _haval(data, 192, 4)
def hav192_5(data: bytes) -> bytes: return _haval(data, 192, 5)
def hav224_3(data: bytes) -> bytes: return _haval(data, 224, 3)
def hav224_4(data: bytes) -> bytes: return _haval(data, 224, 4)
def hav224_5(data: bytes) -> bytes: return _haval(data, 224, 5)
def hav256_3(data: bytes) -> bytes: return _haval(data, 256, 3)
def hav256_4(data: bytes) -> bytes: return _haval(data, 256, 4)
def hav256_5(data: bytes) -> bytes: return _haval(data, 256, 5)
