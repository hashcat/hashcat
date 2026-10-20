#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import os

from argon2.low_level import Type, hash_secret_raw

from lib.test_helpers import random_number, split_hash_word

# Google fscrypt login/custom protector (google/fscrypt, crypto/crypto.go). The password is run
# through Argon2id to a 32-byte wrapping key, HKDF-SHA256 splits that into an encryption key and an
# auth key, and the stored hmac is HMAC-SHA256(auth_key, iv || encrypted_key). Cracking checks only
# that mac, so the iv and encrypted_key here are random: hashcat never decrypts them.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def _hkdf_keys(wrapping_key):
  # hkdf.New(sha256, key, nil, nil): extract with a 32-byte zero salt, then expand with empty info.
  prk = hmac.new(b"\x00" * 32, wrapping_key, hashlib.sha256).digest()
  t1 = hmac.new(prk, b"\x01", hashlib.sha256).digest()
  t2 = hmac.new(prk, t1 + b"\x02", hashlib.sha256).digest()
  return t1, t2  # enc_key, auth_key


def module_generate_hash(word, salt, iv=None, encrypted_key=None, t=None, m=None, p=None):
  if t is None:
    t = random_number(1, 4)

  if p is None:
    p = random_number(1, 4)

  if m is None:
    m = (1 << random_number(8, 12)) + 8 * int(p)  # keep m >= 8*p so the segment length is valid

  if iv is None:
    iv = os.urandom(16)

  if encrypted_key is None:
    encrypted_key = os.urandom(32)

  salt_bin = bytes.fromhex(salt)

  wrapping_key = hash_secret_raw(word, salt_bin, int(t), int(m), int(p), 32, Type.ID, version=19)

  _, auth_key = _hkdf_keys(wrapping_key)

  mac = hmac.new(auth_key, iv + encrypted_key, hashlib.sha256).digest()

  return "$fscrypt$%d*%d*%d*%s*%s*%s*%s" % (
    int(t), int(m), int(p), salt_bin.hex(), iv.hex(), encrypted_key.hex(), mac.hex())


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  if not hash_str.startswith("$fscrypt$"):
    return None

  data = hash_str.split("*")

  if len(data) != 7:
    return None

  t = int(data[0].split("$fscrypt$")[1])
  m = int(data[1])
  p = int(data[2])
  salt = data[3]
  iv = bytes.fromhex(data[4])
  encrypted_key = bytes.fromhex(data[5])

  new_hash = module_generate_hash(word, salt, iv, encrypted_key, t, m, p)

  return (new_hash, word)
