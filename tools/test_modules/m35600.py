#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import gostcrypto

from lib import shacrypt

# gost12512crypt: the SHA-crypt shape over Streebog-512, with its own round schedule and output
# transposition. The digests are used in gostcrypto's byte order, not reversed.
#
# Every message is hashed in one call. gostcrypto's update () only keeps the state right while what
# it has been fed is a whole number of 64 byte blocks.

DEFAULT_ROUNDS = 5000

C_DIGEST_OFFSETS = (
  (0, 3), (5, 1), (5, 3), (1, 2), (5, 1), (5, 3), (1, 3),
  (4, 1), (5, 3), (1, 3), (5, 0), (5, 3), (1, 3), (5, 1),
  (4, 3), (1, 3), (5, 1), (5, 2), (1, 3), (5, 1), (5, 3),
)

TRANSPOSE_512 = (
  42, 21,  0,  1, 43, 22, 23,  2, 44, 45, 24,  3,  4, 46, 25, 26,
   5, 47, 48, 27,  6,  7, 49, 28, 29,  8, 50, 51, 30,  9, 10, 52,
  31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
  16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
)

HASH64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def H(data):
  return bytes(gostcrypto.gosthash.new("streebog512", data=bytearray(data)).digest())


def encode_bytes(source):
  chunks, tail = divmod(len(source), 3)

  out = []

  for k in range(chunks):
    v1, v2, v3 = source[3 * k:3 * k + 3]

    out += [v1 & 0x3f, ((v2 & 0x0f) << 2) | (v1 >> 6), ((v3 & 0x03) << 4) | (v2 >> 4), v3 >> 2]

  if tail == 1:
    v1 = source[-1]

    out += [v1 & 0x3f, v1 >> 6]
  elif tail == 2:
    v1, v2 = source[-2:]

    out += [v1 & 0x3f, ((v2 & 0x0f) << 2) | (v1 >> 6), v2 >> 4]

  return bytes(HASH64[v] for v in out).decode()


def gost12_512_crypt(pwd, salt, rounds):
  db = H(pwd + salt + pwd)

  a_buf = pwd + salt + (db * ((len(pwd) + len(db) - 1) // len(db)))[:len(pwd)]

  i = len(pwd)

  while i:
    a_buf += db if (i & 1) else pwd
    i >>= 1

  da = H(a_buf)

  dp = (H(pwd * len(pwd)) * ((len(pwd) + 63) // 64))[:len(pwd)]

  ds = H(salt * (16 + da[0]))[:len(salt)]

  perms = [dp, dp + dp, dp + ds, dp + ds + dp, ds + dp, ds + dp + dp]

  data = [(perms[e], perms[o]) for e, o in C_DIGEST_OFFSETS]

  dc = da

  blocks, tail = divmod(rounds, 42)

  for _ in range(blocks):
    for even, odd in data:
      dc = H(odd + H(dc + even))

  if tail:
    for even, odd in data[:tail >> 1]:
      dc = H(odd + H(dc + even))

    if tail & 1:
      dc = H(dc + data[tail >> 1][0])

  return encode_bytes(bytes(dc[o] for o in TRANSPOSE_512))


def module_constraints():
  return [[0, 256], [0, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  rounds = DEFAULT_ROUNDS if iterations is None else int(iterations)

  digest = gost12_512_crypt(word, salt.encode(), rounds)

  if rounds == DEFAULT_ROUNDS:
    return "$gost12512hash$%s$%s" % (salt, digest)

  return "$gost12512hash$rounds=%d$%s$%s" % (rounds, salt, digest)


def module_verify_hash(line):
  parsed = shacrypt.parse(line)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
