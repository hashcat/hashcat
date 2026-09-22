#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import struct

from Crypto.Cipher import Blowfish

from lib.test_helpers import random_bytes

# Password Safe v2. Like m05200 this is OPTS_TYPE_BINARY_HASHFILE, so the oracle prints the file
# in base64 and test.sh decodes it back before handing it to hashcat.
#
# The header module_hash_decode reads is 56 bytes:
#
#   RandStuff(8) || RandHash(20) || Salt(20, unused) || IV(8, unused)
#
# and RandHash comes out of
#
#   key    = SHA1(RandStuff || 0x00 0x00 || password)
#   block  = Blowfish-encrypt(RandStuff) x 1000, under that key
#   digest = SHA1(block || 0x00 0x00)
#
# with two quirks the kernel reproduces and this has to match. RandStuff is fed to Blowfish as two
# little-endian words rather than the usual big-endian pair, and the final SHA-1 starts from an
# all-zero state instead of the standard initial values ("yep, not a bug", as m09000-pure.cl puts
# it).
#
# The password is capped at 45 characters because the kernel runs exactly one SHA-1 block, and 10
# bytes of it are already spent on RandStuff and the two zero bytes.

HEADER_LEN = 56
TAIL_LEN   = 112


def module_constraints():
  return [[0, 45], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def _sha1_zero_state(msg):
  h = [0, 0, 0, 0, 0]

  b = msg + b"\x80"

  while len(b) % 64 != 56:
    b += b"\x00"

  b += struct.pack(">Q", len(msg) * 8)

  for off in range(0, len(b), 64):
    w = list(struct.unpack(">16I", b[off:off + 64]))

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

  return b"".join(struct.pack(">I", x) for x in h)


def _rand_hash(word, rand_stuff):
  key = hashlib.sha1(rand_stuff + b"\x00\x00" + word).digest()

  bf    = Blowfish.new(key, Blowfish.MODE_ECB)
  block = struct.pack(">II", *struct.unpack("<II", rand_stuff))

  for _ in range(1000):
    block = bf.encrypt(block)

  return _sha1_zero_state(struct.pack("<II", *struct.unpack(">II", block)) + b"\x00\x00")


def module_generate_hash(word, salt, iterations=None):
  rand_stuff = bytes.fromhex(salt)

  header = rand_stuff + _rand_hash(word, rand_stuff) + random_bytes(28)

  return base64.b64encode(header + random_bytes(TAIL_LEN)).decode("ascii")


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    raw = base64.b64decode(hash_in, validate=True)
  except Exception:
    return None

  if len(raw) < HEADER_LEN:
    return None

  rand_stuff = raw[:8]

  if _rand_hash(word, rand_stuff) != raw[8:28]:
    return None

  # the salt, the IV and the tail are whatever the artifact carried, so the file rebuilds byte for
  # byte

  return (base64.b64encode(raw).decode("ascii"), word)
