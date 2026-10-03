#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

import hashlib

from Crypto.Cipher import ARC4

from lib.test_helpers import random_number, split_hash_word

# PDF 1.4 - 1.6 with the owner (edit) password. Based on m10500 but recovering the O value too, so
# the O side is computed from the owner password and, when the user password is known, folded into
# the RC4 input. Revision 3 or 4, 128 bit key.

PDF_PADDING = bytes([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56,
  0xff, 0xfa, 0x01, 0x08, 0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
])


def module_constraints():
  return [[0, 15], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def _md5(data):
  return hashlib.md5(data).digest()


def _as_bytes(word):
  return word if isinstance(word, bytes) else word.encode("latin-1")


def pdf_compute_encryption_key_user(word, id_hex, o, P, R, enc):
  word = _as_bytes(word)

  data = word
  data += PDF_PADDING[0:32 - len(word)]
  data += bytes.fromhex(o)
  data += struct.pack("<I", P & 0xffffffff)
  data += bytes.fromhex(id_hex)

  if R >= 4:
    if not enc:
      data += struct.pack("<I", (-1) & 0xffffffff)

  res = _md5(data)

  if R >= 3:
    for _ in range(50):
      res = _md5(res)

  return res


def pdf_compute_encryption_key_owner(word, R):
  word = _as_bytes(word)

  o_digest = _md5(word + PDF_PADDING[0:32 - len(word)])

  if R >= 3:
    for _ in range(50):
      o_digest = _md5(o_digest)

  if R == 2:
    return o_digest[0:8]

  return o_digest[0:16]


def module_generate_hash(word, salt=None, iterations=None, u=None, o=None, P=None,
                         V=None, R=None, enc=None, u_pass=None):
  id_hex = salt

  if u is None:
    u = "0" * 64

  u_save = u

  if o is None:
    o = "0" * 64

  if R is None:
    R = random_number(3, 4)

  if V is None:
    V = 2 if R == 3 else 4

  if P is None:
    P = -4 if R == 3 else -1028

  if enc is None:
    enc = 1 if R == 3 else random_number(0, 1)

  if u_pass is None:
    u_pass = ""

  # USER PASSWORD
  # do not recompute a known $u: without the user password there is no way to regenerate it.

  if u == "0" * 64:
    if u_pass == "":
      res = pdf_compute_encryption_key_user(word, id_hex, o, P, R, enc)
    else:
      res = pdf_compute_encryption_key_user(u_pass, id_hex, o, P, R, enc)

    digest = _md5(PDF_PADDING + bytes.fromhex(id_hex))

    u = ARC4.new(res).encrypt(digest)

    for x in range(1, 20):
      s = bytes(res[i] ^ x for i in range(16))

      u = ARC4.new(s).encrypt(u)

    u += bytes.fromhex(u_save)[16:32]
  else:
    u = bytes.fromhex(u)

  # OWNER PASSWORD
  o_key = pdf_compute_encryption_key_owner(word, R)

  if u_pass == "":
    o = ARC4.new(o_key).encrypt(PDF_PADDING[0:32])
  else:
    up = _as_bytes(u_pass)

    o = ARC4.new(o_key).encrypt(up + PDF_PADDING[0:32 - len(up)])

  if R >= 3:
    for x in range(1, 20):
      s = bytes(o_key[i] ^ x for i in range(16))

      o = ARC4.new(s).encrypt(o)

  if u_pass == "":
    return "$pdf$%d*%d*128*%d*%d*16*%s*32*%s*32*%s" % (V, R, P, enc, id_hex, u.hex(), o.hex())

  return "$pdf$%d*%d*128*%d*%d*16*%s*32*%s*32*%s*%s" % (V, R, P, enc, id_hex, u.hex(), o.hex(), u_pass)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) not in (11, 12):
    return None

  V = int(data[0][5:6])
  R = int(data[1])

  if data[2] != "128":
    return None

  P = int(data[3])
  enc = int(data[4])

  if data[5] != "16":
    return None

  id_hex = data[6]

  if data[7] != "32":
    return None

  u = data[8]

  if data[9] != "32":
    return None

  o = data[10]

  u_pass = data[11] if len(data) == 12 else ""

  return (module_generate_hash(word, id_hex, None, u, o, P, V, R, enc, u_pass), word)
