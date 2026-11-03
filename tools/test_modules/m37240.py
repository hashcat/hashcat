#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# MetaMask with a 32 byte vault. PBKDF2-HMAC-SHA256 of the password over a 32 byte salt, then
# AES-GCM with no tag. The line carries only the first 32 bytes of the ciphertext, which is the
# whole point of the mode: 64 bytes, as mode 26610 needs, decrypt to the start of the mnemonic.
# Those 32 bytes are the same for every vault an HD wallet writes, so generation encrypts that
# prefix and the oracle compares against it.

FIXED_PT = b'[{"type":"HD Key Tree","data":{"'

CT_LEN = 32


def module_constraints():
  return [[8, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, ct=None):
  if iv is None:
    iv = random_hex_string(32)

  salt_bin = bytes.fromhex(salt)
  iv_bin   = bytes.fromhex(iv)

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bin, 10000, 32)

  if ct is None:
    pt = FIXED_PT
  else:
    ct_bin = bytes.fromhex(ct)

    pt = AES.new(key, AES.MODE_GCM, nonce=iv_bin).decrypt(ct_bin)

    if pt != FIXED_PT:
      pt = b""

  pt = pt[:CT_LEN]

  ct_bin = AES.new(key, AES.MODE_GCM, nonce=iv_bin).encrypt(pt)

  return "$metamask-short$%s$%s$%s" % (
    base64.b64encode(salt_bin).decode("ascii"),
    base64.b64encode(iv_bin).decode("ascii"),
    base64.b64encode(ct_bin).decode("ascii"))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:16] != "$metamask-short$":
    return None

  parts = hash_in.split("$")

  if len(parts) < 5:
    return None

  salt, iv, ct = parts[2], parts[3], parts[4]

  try:
    salt_bin = base64.b64decode(salt)
    iv_bin   = base64.b64decode(iv)
    ct_bin   = base64.b64decode(ct)
  except Exception:
    return None

  if len(salt_bin) != 32 or len(iv_bin) != 16 or len(ct_bin) != CT_LEN:
    return None

  return (module_generate_hash(word, salt_bin.hex(), iv_bin.hex(), ct_bin.hex()), word)
