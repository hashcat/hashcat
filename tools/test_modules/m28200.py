#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_hex_string

# Exodus wallet: scrypt(word, salt) gives the AES-256-GCM key that unwraps a 32 byte secret. When a
# stored ciphertext and tag are present the tag is checked; a mismatch or a fresh generate wraps
# random bytes instead, so the emitted line is self consistent either way.


def module_constraints():
  return [[4, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, scrypt_n=16384, scrypt_r=8, scrypt_p=1, iv=None, data=None, tag=None):
  if iv is None:
    iv = random_hex_string(24)

  salt_bin = bytes.fromhex(salt)

  maxmem = 128 * scrypt_n * scrypt_r * (scrypt_p + 2)

  key_bin = hashlib.scrypt(word, salt=salt_bin, n=scrypt_n, r=scrypt_r, p=scrypt_p, dklen=32, maxmem=maxmem)

  iv_bin = bytes.fromhex(iv)

  pt = None

  if data is not None:
    data_bin = bytes.fromhex(data)
    tag_bin = bytes.fromhex(tag)

    aes = AES.new(key_bin, AES.MODE_GCM, nonce=iv_bin)
    pt = aes.decrypt(data_bin)

    try:
      aes.verify(tag_bin)
    except ValueError:
      pt = random_bytes(32)
  else:
    pt = random_bytes(32)

  aes = AES.new(key_bin, AES.MODE_GCM, nonce=iv_bin)
  ct_bin, tag_bin = aes.encrypt_and_digest(pt)

  return "EXODUS:%u:%u:%u:%s:%s:%s:%s" % (
    scrypt_n, scrypt_r, scrypt_p,
    base64.b64encode(salt_bin).decode(),
    base64.b64encode(iv_bin).decode(),
    base64.b64encode(ct_bin).decode(),
    base64.b64encode(tag_bin).decode(),
  )


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[:6] != "EXODUS":
    return None

  fields = hash_in.split(":")

  if len(fields) != 8:
    return None

  _, scrypt_n, scrypt_r, scrypt_p, salt, iv, data, tag = fields

  salt = base64.b64decode(salt)
  iv = base64.b64decode(iv)
  data = base64.b64decode(data)
  tag = base64.b64decode(tag)

  new_hash = module_generate_hash(word, salt.hex(), None, int(scrypt_n), int(scrypt_r), int(scrypt_p), iv.hex(), data.hex(), tag.hex())

  return (new_hash, word)
