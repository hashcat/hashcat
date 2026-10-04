#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_hex_string

# SQLCipher: PBKDF2 derives a 32 byte AES key from the password and page salt, then a 16 byte block
# of zeros is AES-CBC encrypted under that key. type selects the PBKDF2 hash, 1 is HMAC-SHA1 (the
# only one the generator emits), 2 is HMAC-SHA256, 3 is HMAC-SHA512.

_PRF = {1: "sha1", 2: "sha256", 3: "sha512"}


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, type=1, iv=None, enc=None):
  type = 1 if type is None else int(type)

  if iterations is None:
    iterations = random_number(10000, 20000)

  if iv is None:
    iv = random_hex_string(32)

  iterations = int(iterations)

  salt_bin = bytes.fromhex(salt)
  iv_bin = bytes.fromhex(iv)

  key = hashlib.pbkdf2_hmac(_PRF[type], word, salt_bin, iterations, 32)

  if enc is not None:
    enc_bin = bytes.fromhex(enc)

    data = AES.new(key, AES.MODE_CBC, iv_bin).decrypt(enc_bin)

    if data[0:12] != b"\x00" * 12:
      data = b"\xff" * 16
  else:
    data = b"\x00" * 16

  enc_out = AES.new(key, AES.MODE_CBC, iv_bin).encrypt(data)

  return "SQLCIPHER*%d*%d*%s*%s*%s" % (type, iterations, salt_bin.hex(), iv_bin.hex(), enc_out.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith("SQLCIPHER"):
    return None

  fields = hash_in.split("*")

  if len(fields) < 6:
    return None

  _, type, iterations, salt, iv, data = fields[:6]

  return (module_generate_hash(word, salt, iterations, type, iv, data), word)
