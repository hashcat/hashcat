#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Skein-512 version 1.3 with 224, 256, 384 and 512 bit output (Skein-512-224 .. Skein-512-512).
# Neither hashlib nor pycryptodome carries it, so this is a small self contained implementation.

import struct

_R = 0xffffffffffffffff

_C240 = 0x1bd11bdaa9fc1a22

# the word pairs and rotations of 8 consecutive Threefish-512 rounds, the word permutation is folded
# into the pair indices

_PAIRS = [
  ((0, 1), (2, 3), (4, 5), (6, 7)),
  ((2, 1), (4, 7), (6, 5), (0, 3)),
  ((4, 1), (6, 3), (0, 5), (2, 7)),
  ((6, 1), (0, 7), (2, 5), (4, 3)),
]

_ROT = [
  (46, 36, 19, 37), (33, 27, 14, 42), (17, 49, 36, 39), (44, 9, 54, 56),
  (39, 30, 34, 24), (13, 50, 10, 17), (25, 29, 39, 43), (8, 35, 56, 22),
]

# the 16 mixes between an even subkey and the next, and between an odd one and the next

_MIXES = [[], []]

for _d in range(8):
  _MIXES[_d // 4] += [(a, b, r, 64 - r) for (a, b), r in zip(_PAIRS[_d % 4], _ROT[_d])]

_T_CFG = 4
_T_MSG = 48
_T_OUT = 63

_FIRST = 1 << 62
_FINAL = 1 << 63


def _threefish(key, t0, t1, block):
  k = list(key) + [0]

  k[8] = _C240

  for i in range(8): k[8] ^= k[i]

  t = (t0, t1, t0 ^ t1)

  p = list(block)

  for s in range(19):
    # add subkey s before every 4 rounds, and once more after the last

    for i in range(8): p[i] = (p[i] + k[(s + i) % 9]) & _R

    p[5] = (p[5] + t[(s + 0) % 3]) & _R
    p[6] = (p[6] + t[(s + 1) % 3]) & _R
    p[7] = (p[7] + s) & _R

    if s == 18: break

    for a, b, r, l in _MIXES[s % 2]:
      x = (p[a] + p[b]) & _R
      y = p[b]

      p[a] = x
      p[b] = (((y << r) | (y >> l)) & _R) ^ x

  return p


def _ubi(h, msg, ttype):
  # msg is at least one block, the last block is zero padded and the tweak counts real bytes only

  n = len(msg)

  blocks = max(1, (n + 63) // 64)

  data = msg + b"\x00" * (blocks * 64 - n)

  for i in range(blocks):
    m = struct.unpack("<8Q", data[i * 64:(i + 1) * 64])

    t0 = min(n, (i + 1) * 64)

    t1 = ttype << 56

    if i == 0: t1 |= _FIRST
    if i == blocks - 1: t1 |= _FINAL

    e = _threefish(h, t0, t1, m)

    h = [e[j] ^ m[j] for j in range(8)]

  return h


def _iv(out_bits):
  # schema "SHA3", version 1, output length, no tree, 32 bytes in all

  cfg = struct.pack("<4sHHQ", b"SHA3", 1, 0, out_bits) + b"\x00" * 16

  iv = _ubi([0] * 8, cfg, _T_CFG)

  return iv


_IV = {n: _iv(n) for n in (224, 256, 384, 512)}


def _skein(data, out_bits):
  h = _ubi(_IV[out_bits], data, _T_MSG)

  h = _ubi(h, struct.pack("<Q", 0), _T_OUT)

  out = struct.pack("<8Q", *h)[:out_bits // 8]

  return out


def skein224(data: bytes) -> bytes:
  return _skein(data, 224)


def skein256(data: bytes) -> bytes:
  return _skein(data, 256)


def skein384(data: bytes) -> bytes:
  return _skein(data, 384)


def skein512(data: bytes) -> bytes:
  return _skein(data, 512)
