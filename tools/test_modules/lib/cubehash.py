#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# CubeHash16/32 with 224, 256, 384 and 512 bit output, the variant sphlib implements. Neither
# hashlib nor pycryptodome carries it, so this is a small self contained implementation.

import struct

_R = 0xffffffff


def _rounds(x, count):
  # x[0..15] and x[16..31] are the two halves, index bits are j k l m from 8 down to 1

  for _ in range(count):
    for i in range(16): x[16 + i] = (x[16 + i] + x[i]) & _R
    for i in range(16): x[i] = ((x[i] << 7) | (x[i] >> 25)) & _R

    x[0:8], x[8:16] = x[8:16], x[0:8]

    for i in range(16): x[i] ^= x[16 + i]

    for i in (16, 17, 20, 21, 24, 25, 28, 29): x[i], x[i + 2] = x[i + 2], x[i]

    for i in range(16): x[16 + i] = (x[16 + i] + x[i]) & _R
    for i in range(16): x[i] = ((x[i] << 11) | (x[i] >> 21)) & _R

    for i in (0, 1, 2, 3, 8, 9, 10, 11): x[i], x[i + 4] = x[i + 4], x[i]

    for i in range(16): x[i] ^= x[16 + i]

    for i in range(16, 32, 2): x[i], x[i + 1] = x[i + 1], x[i]


def _iv(out_bytes):
  x = [out_bytes, 32, 16] + [0] * 29

  _rounds(x, 160)

  return x


_IV = {n: _iv(n) for n in (28, 32, 48, 64)}


def _cubehash(data, out_bytes):
  x = _IV[out_bytes][:]

  msg = data + b"\x80"
  msg += b"\x00" * ((32 - len(msg)) % 32)

  for off in range(0, len(msg), 32):
    m = struct.unpack("<8I", msg[off:off + 32])

    for i in range(8): x[i] ^= m[i]

    _rounds(x, 16)

  x[31] ^= 1

  _rounds(x, 160)

  out = struct.pack("<16I", *x[:16])[:out_bytes]

  return out


def cube224(data: bytes) -> bytes:
  return _cubehash(data, 28)


def cube256(data: bytes) -> bytes:
  return _cubehash(data, 32)


def cube384(data: bytes) -> bytes:
  return _cubehash(data, 48)


def cube512(data: bytes) -> bytes:
  return _cubehash(data, 64)
