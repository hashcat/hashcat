#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Shabal-224, Shabal-256, Shabal-384 and Shabal-512 (SHA-3 round 2). Neither hashlib nor
# pycryptodome carries it, so this is a small self contained implementation.

import struct

_R = 0xffffffff

# the A, B, C and M indices of each of the 48 permutation steps

_STEPS = []

for _j in range(3):
  for _i in range(16):
    _a = (16 * _j + _i) % 12

    _STEPS.append((_a, (_a + 11) % 12, _i, (_i + 13) % 16, (_i + 9) % 16, (_i + 6) % 16, (8 - _i) % 16))

# A[(11 - k) % 12] += C[(6 - k) % 16] for k = 0..35, in order

_FINAL_ADD = [((11 - k) % 12, (6 - k) % 16) for k in range(36)]


def _perm(a, b, c, m, w):
  a[0] ^= (w >> 0) & _R
  a[1] ^= (w >> 32) & _R

  for i in range(16):
    x = b[i]

    b[i] = ((x << 17) | (x >> 15)) & _R

  for ia, ip, ib, ib1, ib2, ib3, ic in _STEPS:
    xp = a[ip]

    t = (((xp << 15) | (xp >> 17)) * 5) & _R

    v = (((a[ia] ^ t ^ c[ic]) * 3) & _R) ^ b[ib1] ^ (b[ib2] & (b[ib3] ^ _R)) ^ m[ib]

    a[ia] = v

    x = b[ib]

    b[ib] = (((x << 1) | (x >> 31)) & _R) ^ v ^ _R

  for ia, ic in _FINAL_ADD:
    a[ia] = (a[ia] + c[ic]) & _R


def _block(a, b, c, m, w):
  for i in range(16): b[i] = (b[i] + m[i]) & _R

  _perm(a, b, c, m, w)

  for i in range(16): c[i] = (c[i] - m[i]) & _R

  b[:], c[:] = c[:], b[:]


def _iv(out_bits):
  # the initial state is what two blocks of counter words do to an all zero state

  a = [0] * 12
  b = [0] * 16
  c = [0] * 16

  m0 = [out_bits + i for i in range(16)]
  m1 = [out_bits + 16 + i for i in range(16)]

  _block(a, b, c, m0, 0xffffffffffffffff)
  _block(a, b, c, m1, 0)

  return a, b, c


_IV = {n: _iv(n) for n in (224, 256, 384, 512)}


def _shabal(data, out_bits):
  iv = _IV[out_bits]

  a = iv[0][:]
  b = iv[1][:]
  c = iv[2][:]

  msg = data + b"\x80"
  msg += b"\x00" * ((64 - len(msg)) % 64)

  last = len(msg) - 64

  w = 1

  for off in range(0, last, 64):
    _block(a, b, c, struct.unpack("<16I", msg[off:off + 64]), w)

    w += 1

  # the final block is followed by 3 extra permutations with the same counter

  m = struct.unpack("<16I", msg[last:])

  for i in range(16): b[i] = (b[i] + m[i]) & _R

  _perm(a, b, c, m, w)

  for _ in range(3):
    b[:], c[:] = c[:], b[:]

    _perm(a, b, c, m, w)

  words = out_bits // 32

  out = struct.pack("<%dI" % words, *b[16 - words:])

  return out


def shabal224(data: bytes) -> bytes:
  return _shabal(data, 224)


def shabal256(data: bytes) -> bytes:
  return _shabal(data, 256)


def shabal384(data: bytes) -> bytes:
  return _shabal(data, 384)


def shabal512(data: bytes) -> bytes:
  return _shabal(data, 512)
