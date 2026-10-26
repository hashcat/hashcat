#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib import iclass
from lib.test_helpers import random_bytes, split_hash_word

# HID iClass Standard brute force. The password is the 8 byte master key: it DES-encrypts the card
# serial number, hash0 turns that into the diversified key, and the iClass MAC runs over two nonces.

PI = [
  0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D,
  0x2E, 0x33, 0x35, 0x39, 0x36, 0x3A, 0x3C, 0x47,
  0x4B, 0x4D, 0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A,
  0x5C, 0x63, 0x65, 0x66, 0x69, 0x6A, 0x6C, 0x71,
  0x72, 0x74, 0x78,
]


def _hash0(des_out0, des_out1):
  x = (des_out0 >> 24) & 0xFF
  y = (des_out0 >> 16) & 0xFF
  hi = des_out0 & 0xFFFF
  lo = des_out1

  zs = [0] * 8
  zs[0] = lo & 0x3F
  zs[1] = (lo >> 6) & 0x3F
  zs[2] = (lo >> 12) & 0x3F
  zs[3] = (lo >> 18) & 0x3F
  zs[4] = (lo >> 24) & 0x3F
  zs[5] = ((hi & 0x0F) << 2) | (lo >> 30)
  zs[6] = (hi >> 4) & 0x3F
  zs[7] = (hi >> 10) & 0x3F

  zp = [0] * 8
  zp[0] = (zs[0] % 63) + 0
  zp[1] = (zs[1] % 62) + 1
  zp[2] = (zs[2] % 61) + 2
  zp[3] = (zs[3] % 60) + 3
  zp[4] = (zs[4] % 64) + 0
  zp[5] = (zs[5] % 63) + 1
  zp[6] = (zs[6] % 62) + 2
  zp[7] = (zs[7] % 61) + 3

  for i in range(3, 0, -1):
    for j in range(i - 1, -1, -1):
      if zp[i] == zp[j]:
        zp[i] = j

  for i in range(7, 4, -1):
    for j in range(i - 1, 3, -1):
      if zp[i] == zp[j]:
        zp[i] = j - 4

  p = PI[x % 35]

  if x & 1:
    p = (~p) & 0xFF

  li = 0
  ri = 4
  zt = [0] * 8

  for bit in range(8):
    if (p >> bit) & 1:
      zt[bit] = zp[li] + 1
      li += 1
    else:
      zt[bit] = zp[ri]
      ri += 1

  div_key = [0] * 8

  for i in range(8):
    y_bit = (y >> i) & 1
    zt_i = (zt[i] << 1) & 0xFE
    p_i = (p >> i) & 1

    ki = y_bit << 7

    if ki:
      ki |= (~zt_i) & 0x7E
      ki |= p_i & 1
      ki = (ki + 1) & 0xFF
    else:
      ki |= zt_i & 0x7E
      ki |= (~p_i) & 1

    div_key[i] = ki & 0xFF

  return div_key


def module_constraints():
  return [[8, 8], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if salt:
    parts = salt.split("$")
    csn_hex = parts[0]
    ccnr1_hex = parts[1]
    ccnr2_hex = parts[2] if len(parts) > 2 else parts[1]
  else:
    csn_hex = random_bytes(8).hex()
    ccnr1_hex = random_bytes(12).hex()
    ccnr2_hex = ccnr1_hex

  ct = DES.new(word, DES.MODE_ECB).encrypt(bytes.fromhex(csn_hex))

  des_out0 = (ct[0] << 24) | (ct[1] << 16) | (ct[2] << 8) | ct[3]
  des_out1 = (ct[4] << 24) | (ct[5] << 16) | (ct[6] << 8) | ct[7]

  div_key = _hash0(des_out0, des_out1)

  mac1 = iclass.mac([iclass.reflect8(b) for b in bytes.fromhex(ccnr1_hex)], div_key)
  mac2 = iclass.mac([iclass.reflect8(b) for b in bytes.fromhex(ccnr2_hex)], div_key)

  return "$iclass$%s$%s$%08x$%s$%08x" % (csn_hex, ccnr1_hex, mac1, ccnr2_hex, mac2)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$iclass$"):
    return None

  fields = hash_in[len("$iclass$"):].split("$")

  if len(fields) < 3:
    return None

  ccnr2 = fields[3] if len(fields) >= 5 else fields[1]
  salt = "%s$%s$%s" % (fields[0], fields[1], ccnr2)

  return (module_generate_hash(word, salt), word)
