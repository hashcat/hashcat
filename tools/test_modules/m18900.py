#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_hex_string

# Android FDE (Samsung DEK). PBKDF2-HMAC-SHA1 over the user salt derives an AES-256 key that CBC
# encrypts the 83 byte master key blob. Crypt::CBC "standard" padding is PKCS#7 whose decrypt strips
# the last byte's count without validating it, so the padding is done by hand to match.


def _pad(data):
  n = 16 - (len(data) % 16)

  return data + bytes([n]) * n


def _unpad(data):
  return data[:-data[-1]]


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, version=None, iterations=None, user_salt=None,
                         ck_salt=None, user_iv=None, masterkey_blob=None):
  # the runner hands iter (or None) in the 3rd slot, which the perl oracle reads as version, so a
  # missing value falls back to 5 the same way its shift // 5 does
  version = 5 if version is None else version

  iterations = 10000 if iterations is None else int(iterations)

  # draw defaults in the same order the perl oracle does, so a seeded run stays on one rng stream

  if user_salt is None:
    user_salt = random_hex_string(128)

  if ck_salt is None:
    ck_salt = random_hex_string(128)

  if user_iv is None:
    user_iv = random_hex_string(32)

  user_salt_bin = bytes.fromhex(user_salt)

  key_bin = hashlib.pbkdf2_hmac("sha1", word, user_salt_bin, iterations, 32)

  iv_bin = bytes.fromhex(user_iv)

  decrypted_bin = random_bytes(83)

  if masterkey_blob is not None:
    encrypted_bin = bytes.fromhex(masterkey_blob)

    test_bin = _unpad(AES.new(key_bin, AES.MODE_CBC, iv_bin).decrypt(encrypted_bin))

    if len(test_bin) == 83:
      decrypted_bin = test_bin

  encrypted_bin = AES.new(key_bin, AES.MODE_CBC, iv_bin).encrypt(_pad(decrypted_bin))

  return "$ab$%u*0*%u*%s*%s*%s*%s" % (int(version), iterations, user_salt, ck_salt,
                                      user_iv, encrypted_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split("*")

  if len(fields) != 7:
    return None

  tag, cipher, iterations, user_salt, ck_salt, user_iv, masterkey_blob = fields

  tag_parts = tag.split("$")

  if len(tag_parts) != 3:
    return None

  if tag_parts[1] != "ab" or cipher != "0":
    return None

  version = tag_parts[2]

  new_hash = module_generate_hash(word, None, version, iterations, user_salt, ck_salt,
                                  user_iv, masterkey_blob)

  return (new_hash, word)
