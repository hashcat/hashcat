#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

# Kremlin Encrypt 3.0 with NewDES. The stored string is $kgb$<8-byte salt>$<20 byte hash>, and the
# derivation is
#
#   sha1sum = SHA1(password)
#   key     = key_expansion(sha1sum)          # 60 bytes, from 15 of its bytes
#   block   = new_des(salt) x 1000            # NewDES over the 8-byte salt
#   hash    = SHA1(block || password)
#
# with one catch: Kremlin's SHA-1 is byte-swapped. It feeds its message in as little-endian 32-bit
# words and writes the trailing bit length little-endian too, which the kernel reproduces with
# sha1_final_32700 (). So the SHA-1 here is the standard one run over the message with every four
# byte group reversed and the length field reversed; everything else about it is unchanged.

# OpenCL/m32700-pure.cl newdes_rotor[256]

ROTOR = bytes.fromhex(
  "2089efbc667ddd48d444512556ed939546e5117c73cf21147a8f19d733b78a8e"
  "92d36ead01e4bd0e674ea224fda774ff9e2db93262a8faeb368dc3f7f03f9402"
  "e0a9d6b43e16756c13aca19fa02f2babc2afb238c47017dc5915a4829d0855fb"
  "d82c5eb3e2265a7728ca22ce2345e7f61d6d4a47b0063c91410d4d970c7f5fc7"
  "396505e896d28118b50a79bb30c18bfcdb4058e960805035bf90da0b6a849b68"
  "5b881f2af3427e871e1a57bab69af27b52a6d02798be71cd7269e15449a3636f"
  "cc3dc8d9aa0fc61cc0fe86eade07ecf8c929b19c5c8343f9f5b8cb09f1001b2e"
  "85ae4b125dd164784cd51053046b8c343a3703f461c5eee376314fe6dfa5993b")

ROUNDS = 1000


def module_constraints():
  return [[0, 256], [16, 16], [0, 15], [16, 16], [-1, -1]]


def _sha1_kremlin(msg):
  h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

  bitlen = (len(msg) * 8) & 0xFFFFFFFF

  b = msg + b"\x80"

  while len(b) % 64 != 56:
    b += b"\x00"

  m = b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))
  m += b"\x00" * 4 + struct.pack("<I", bitlen)

  for off in range(0, len(m), 64):
    w = list(struct.unpack(">16I", m[off:off + 64]))

    for i in range(16, 80):
      v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]

      w.append(((v << 1) | (v >> 31)) & 0xFFFFFFFF)

    a, bb, c, d, e = h

    for i in range(80):
      if i < 20:
        f, k = (bb & c) | ((~bb & 0xFFFFFFFF) & d), 0x5A827999
      elif i < 40:
        f, k = bb ^ c ^ d, 0x6ED9EBA1
      elif i < 60:
        f, k = (bb & c) | (bb & d) | (c & d), 0x8F1BBCDC
      else:
        f, k = bb ^ c ^ d, 0xCA62C1D6

      t = ((((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[i]) & 0xFFFFFFFF

      e, d, c, bb, a = d, c, ((bb << 30) | (bb >> 2)) & 0xFFFFFFFF, a, t

    h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, bb, c, d, e])]

  return h


def _key_expansion(sha1sum):
  key = []

  for count in range(15):
    shi = sha1sum[count]

    key += [shi, shi ^ sha1sum[7], shi ^ sha1sum[8], shi ^ sha1sum[9]]

  return key


def _new_des(b, key):
  k = iter(key)

  for _ in range(8):
    b[4] ^= ROTOR[b[0] ^ next(k)]
    b[5] ^= ROTOR[b[1] ^ next(k)]
    b[6] ^= ROTOR[b[2] ^ next(k)]
    b[7] ^= ROTOR[b[3] ^ next(k)]

    b[1] ^= ROTOR[b[4] ^ next(k)]
    b[2] ^= ROTOR[b[4] ^ b[5]]
    b[3] ^= ROTOR[b[6] ^ next(k)]
    b[0] ^= ROTOR[b[7] ^ next(k)]

  b[4] ^= ROTOR[b[0] ^ next(k)]
  b[5] ^= ROTOR[b[1] ^ next(k)]
  b[6] ^= ROTOR[b[2] ^ next(k)]
  b[7] ^= ROTOR[b[3] ^ next(k)]


def module_generate_hash(word, salt, iterations=None):
  salt_raw = bytes.fromhex(salt)

  sha1sum = b"".join(struct.pack(">I", x) for x in _sha1_kremlin(word))

  key = _key_expansion(sha1sum)

  block = list(salt_raw)

  for _ in range(ROUNDS):
    _new_des(block, key)

  digest = "".join("%08x" % x for x in _sha1_kremlin(bytes(block) + word))

  return "$kgb$%s$%s" % (salt, digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"$")

  if len(parts) != 4 or parts[1] != b"kgb" or len(parts[2]) != 16:
    return None

  try:
    salt = parts[2].decode("ascii")

    bytes.fromhex(salt)
  except (UnicodeDecodeError, ValueError):
    return None

  return (module_generate_hash(word, salt), word)
