#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii

from Crypto.Cipher import AES

from lib import md5crypt
from lib.test_helpers import random_hex_string, split_hash_word

# Juniper IVE: an ordinary md5crypt with the salt danastre, zero padded to 64 bytes and encrypted with
# AES-128-CBC under the key module_00501.c carries. The stored string is base64 of a 12 byte IV and
# the ciphertext; the cipher's IV is those 12 bytes and four zeros. The IV takes the salt slot, 24
# hex characters.

KEY = bytes.fromhex("a6707a7e8df91059dea70ae52f9c2442")


def module_constraints():
  return [[0, 256], [24, 24], [0, 15], [24, 24], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iv_hex = salt if salt and len(salt) == 24 else random_hex_string(24)

  iv = bytes.fromhex(iv_hex)

  plain = md5crypt.md5_crypt(b"$1$", 1000, word, b"danastre").encode()

  data = AES.new(KEY, AES.MODE_CBC, iv + b"\x00" * 4).encrypt(plain + b"\x00" * (64 - len(plain)))

  return base64.b64encode(iv + data).decode()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  try:
    data = base64.b64decode(hash_in)
  except binascii.Error:
    return None

  if len(data) != 76:
    return None

  return (module_generate_hash(word, data[:12].hex()), word)
