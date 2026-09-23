#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

import hashlib

from Crypto.Cipher import ARC4

from lib.test_helpers import random_number, split_hash_word

# PDF 1.3 - 1.6 (Acrobat 4 - 8) with a 40-bit RC4 key: the standard security handler of m10500 with
# the key shortened from 16 bytes to 5. KEY_LEN is that one number, and it drives the truncation in
# the 50 round key hardening, the RC4 key, and the width of the XOR in the 19 U rounds.
#
# The parser accepts V 1 or 2 with R 3 only, and insists on 40 in the bits field.

PDF_PADDING = bytes([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56,
  0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
])

KEY_LEN = 5  # 40 bits


def module_constraints():
  return [[0, 15], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def _md5(data):
  return hashlib.md5(data).digest()


def pdf_compute_encryption_key(word_buf, padding, id_hex, o, P):
  data = word_buf
  data += padding[0:32 - len(word_buf)]
  data += bytes.fromhex(o)
  data += struct.pack("<I", P & 0xffffffff)
  data += bytes.fromhex(id_hex)

  res = _md5(data)

  # R 3 hardening, over the first KEY_LEN bytes only
  for _ in range(50):
    res = _md5(res[0:KEY_LEN])

  return res[0:KEY_LEN]


def module_generate_hash(word, salt=None, iterations=None, u=None, o=None, P=None, V=None):
  id_hex = salt

  if u is None:
    u = "0" * 64

  u_save = u

  if o is None:
    o = "0" * 64

  if P is None:
    P = -4

  if V is None:
    V = random_number(1, 2)

  R = 3  # the only revision this mode parses

  key = pdf_compute_encryption_key(word, PDF_PADDING, id_hex, o, P)

  digest = _md5(PDF_PADDING + bytes.fromhex(id_hex))

  u = ARC4.new(key).encrypt(digest)

  for x in range(1, 20):
    s = bytes(key[i] ^ x for i in range(KEY_LEN))

    u = ARC4.new(s).encrypt(u)

  # only the first 16 bytes of U are checked; the rest is arbitrary padding
  u += bytes.fromhex(u_save)[16:32]

  return "$pdf$%d*%d*40*%d*1*16*%s*32*%s*32*%s" % (V, R, P, id_hex, u.hex(), o)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 11:
    return None

  V = int(data[0][5:6])
  R = int(data[1])

  if data[2] != "40":
    return None

  P = int(data[3])

  if data[5] != "16":
    return None

  id_hex = data[6]

  if data[7] != "32":
    return None

  u = data[8]

  if data[9] != "32":
    return None

  o = data[10]

  if R != 3:
    return None

  return (module_generate_hash(word, id_hex, None, u, o, P, V), word)
