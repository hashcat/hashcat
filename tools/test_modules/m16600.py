#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string, split_hash_word

# Electrum wallet salt type 1. The key is a double SHA256 of the password, used as a raw AES 256 CBC
# key with no padding. Only salt type 1 is reproduced here, as in the perl.

_HEX_RE = re.compile(rb"^[0-9a-f]+$")


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, iv=None, salt_type=None, plain_bin=None):
  if not iv:
    iv = random_hex_string(32)

  salt_type = salt_type or 1

  if str(salt_type) != "1":
    raise ValueError("currently only salt_type 1 supported")

  key_bin = hashlib.sha256(hashlib.sha256(word).digest()).digest()

  iv_bin = bytes.fromhex(iv)

  if plain_bin is not None:
    encrypted_bin = bytes.fromhex(plain_bin)

    test = AES.new(key_bin, AES.MODE_CBC, iv_bin).decrypt(encrypted_bin)

    if _HEX_RE.match(test):
      plain_bin = test
    else:
      plain_bin = b"\xff" * 16
  else:
    plain_bin = bytes.fromhex("30313233343536373839616263646566")

  encrypted = AES.new(key_bin, AES.MODE_CBC, iv_bin).encrypt(plain_bin)

  return "$electrum$%s*%s*%s" % (salt_type, iv, encrypted.hex())


def module_verify_hash(line):
  parsed = split_hash_word(line)

  if parsed is None:
    return None

  hash_in, word = parsed

  data = hash_in.split("*")

  if len(data) != 3:
    return None

  mode, iv, encrypted = data

  mode_parts = mode.split("$")

  if len(mode_parts) < 3:
    return None

  signature = mode_parts[1]
  salt_type = mode_parts[2]

  if signature != "electrum":
    return None

  new_hash = module_generate_hash(word, iv, salt_type, encrypted)

  return (new_hash, word)
