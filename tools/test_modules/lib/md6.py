#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# MD6 with the default parameters of the reference md6_hash: no key, L = 64 (a full 4-ary tree)
# and 40 + d / 4 rounds. Neither hashlib nor pycryptodome carries it.

_M = 0xffffffffffffffff

_Q = [
  0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1, 0xe8fb23908d9f06f1,
  0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41, 0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d,
  0x4ad12aae0a6d6031, 0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31,
  0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb,
]

# right and left shift amounts of the 16 steps in a round

_RS = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12]
_LS = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9]

_S0    = 0x0123456789abcdef
_SMASK = 0x7311c2812425cfa0

_L = 64


def _compress(n: list, r: int) -> list:
  # n is the 89 word input, the output is the last 16 words computed

  a = list(n)

  s = _S0

  for _ in range(r):
    i = len(a)

    for step in range(16):
      x = s ^ a[i - 89] ^ a[i - 17] ^ (a[i - 18] & a[i - 21]) ^ (a[i - 31] & a[i - 67])
      x ^= x >> _RS[step]

      a.append(x ^ ((x << _LS[step]) & _M))

      i += 1

    s = ((s << 1) & _M) ^ (s >> 63) ^ (s & _SMASK)

  out = a[-16:]

  return out


def _node(words: list, ell: int, idx: int, z: int, p: int, r: int, d: int) -> list:
  u = (ell << 56) | idx
  v = (r << 48) | (_L << 40) | (z << 36) | (p << 20) | d

  c = _compress(_Q + [0] * 8 + [u, v] + words, r)

  return c


def _md6(data: bytes, d: int) -> bytes:
  # level 1: 512 byte leaves of big endian words, at least one even for an empty message

  nodes = []

  for off in range(0, max(len(data), 1), 512):
    chunk = data[off:off + 512]

    padded = chunk + b"\x00" * (512 - len(chunk))

    words = [int.from_bytes(padded[i:i + 8], "big") for i in range(0, 512, 8)]

    nodes.append((words, 4096 - 8 * len(chunk)))

  r   = 40 + d // 4
  ell = 1

  while True:
    top = 1 if len(nodes) == 1 else 0

    chain = []

    for idx in range(len(nodes)):
      words, p = nodes[idx]

      chain.append(_node(words, ell, idx, top, p, r, d))

    if top == 1: break

    # 4 chaining values of 16 words fill one node of the next level

    nodes = []

    for off in range(0, len(chain), 4):
      group = chain[off:off + 4]

      words = [x for cv in group for x in cv]

      nodes.append((words + [0] * (64 - len(words)), 4096 - 1024 * len(group)))

    ell += 1

  out = b"".join(x.to_bytes(8, "big") for x in chain[0])

  digest = out[128 - d // 8:]

  return digest


def md6128(data: bytes) -> bytes:
  digest = _md6(data, 128)

  return digest


def md6256(data: bytes) -> bytes:
  digest = _md6(data, 256)

  return digest


def md6512(data: bytes) -> bytes:
  digest = _md6(data, 512)

  return digest
