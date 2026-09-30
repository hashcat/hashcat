#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_hex_string

# Terra Station wallet. PBKDF2-HMAC-SHA1 (100 rounds) of the password makes an AES-256 key that CBC
# encrypts 64 bytes followed by a full 0x10 padding block; the salt and iv are stored in front of the
# base64 ciphertext.

ITERATIONS = 100


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, data=None):
  salt_bin = salt.encode("latin-1") if isinstance(salt, str) else salt

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, ITERATIONS, 32)

  if iv is None:
    iv = random_bytes(16)

  if data is None:
    data = random_hex_string(64).encode("latin-1") + b"\x10" * 16
  else:
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    if data[64:80] != b"\x10" * 16:
      data = b"\x00" * 80

  encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(data)

  return "%s%s%s" % (salt_bin.hex(), iv.hex(), base64.b64encode(encrypted).decode("ascii"))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if len(hash_in) != 32 + 32 + 108:
    return None

  salt, iv, data = hash_in[0:32], hash_in[32:64], hash_in[64:172]

  try:
    salt = bytes.fromhex(salt)
    iv = bytes.fromhex(iv)
    data = base64.b64decode(data)
  except (ValueError, base64.binascii.Error):
    return None

  if len(data) != 80:
    return None

  return (module_generate_hash(word, salt, iv, data), word)
