#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

# MD6-256. No stdlib or PyPI binding exists for MD6, so the compression function
# and the single node case of the mode of operation are reproduced here. The
# password constraint is 0 to 55 bytes, which always fits one data block, so the
# hash is a single compression at level 1 with the final flag set. Verified byte
# for byte against perl's Digest::MD6.

MASK = (1 << 64) - 1

# Q: fractional part of sqrt(6), 15 words
Q = [
  0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1, 0xe8fb23908d9f06f1,
  0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41, 0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d,
  0x4ad12aae0a6d6031, 0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31,
  0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb,
]

S0 = 0x0123456789abcdef
SMASK = 0x7311c2812425cfa0

# per step right and left shift amounts
RS = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12]
LS = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9]

# tap positions into the shift register, t5 == n
T0, T1, T2, T3, T4, T5 = 17, 18, 21, 31, 67, 89

N_WORDS = 89


def _compress(N, r):
  A = list(N) + [0] * (16 * r)

  S = S0
  i = N_WORDS
  for _ in range(r):
    for step in range(16):
      x = S
      x ^= A[i + step - T5]
      x ^= A[i + step - T0]
      x ^= A[i + step - T1] & A[i + step - T2]
      x ^= A[i + step - T3] & A[i + step - T4]
      x ^= x >> RS[step]
      x ^= (x << LS[step]) & MASK
      A[i + step] = x & MASK
    S = (((S << 1) & MASK) ^ (S >> 63) ^ (S & SMASK)) & MASK
    i += 16

  return A[i - 16:i]


def md6_256(msg):
  d = 256
  keylen = 0
  L = 64
  r = 40 + (d // 4)  # unkeyed default

  ell = 1
  index = 0
  z = 1  # single node, so it is also the final one

  m_bits = len(msg) * 8
  data = msg + b"\x00" * (512 - len(msg))
  B = list(struct.unpack(">64Q", data))

  p = 512 * 8 - m_bits

  K = [0] * 8
  U = ((ell & 0xff) << 56) | index
  V = ((r & 0xfff) << 48) | ((L & 0xff) << 40) | ((z & 0xf) << 36) \
      | ((p & 0xffff) << 20) | ((keylen & 0xff) << 12) | (d & 0xfff)

  N = Q + K + [U, V] + B

  out = _compress(N, r)

  # the digest is the rightmost d bits of the 16 word output
  words = out[16 - d // 64:]

  return b"".join(struct.pack(">Q", w) for w in words).hex()


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  return md6_256(word)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if not hash_in:
    return None

  return (module_generate_hash(word), word)
