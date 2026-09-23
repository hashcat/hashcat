#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# Mozilla key4.db (AES). sha1 of the global salt and password is stretched by PBKDF2-HMAC-SHA256 with
# the entry salt into an AES-256 key that CBC encrypts the fixed check string "password-check\x02\x02".

CHECK = b"password-check\x02\x02"


def module_constraints():
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, global_salt, entry_salt=None, iterations=None, iv=None, ct=None):
  entry_salt = random_hex_string(64) if entry_salt is None else entry_salt
  iterations = 10000 if iterations is None else int(iterations)
  iv = random_hex_string(32) if iv is None else iv

  global_salt_bin = bytes.fromhex(global_salt)
  entry_salt_bin = bytes.fromhex(entry_salt)
  iv_bin = bytes.fromhex(iv)

  global_key = hashlib.sha1(global_salt_bin + word).digest()

  entry_key = hashlib.pbkdf2_hmac("sha256", global_key, entry_salt_bin, iterations, 32)

  if ct is not None:
    pt = AES.new(entry_key, AES.MODE_CBC, iv_bin).decrypt(bytes.fromhex(ct))

    if pt != CHECK:
      pt = b"\xff" * 16
  else:
    pt = CHECK

  ct_bin = AES.new(entry_key, AES.MODE_CBC, iv_bin).encrypt(pt)

  return "$mozilla$*AES*%s*%s*%d*%s*%s" % (
    global_salt_bin.hex(), entry_salt_bin.hex(), iterations, iv_bin.hex(), ct_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:9] != "$mozilla$":
    return None

  data = hash_in.split("*")

  if len(data) != 7 or data[1] != "AES":
    return None

  _, _, global_salt, entry_salt, iterations, iv, ct = data

  return (module_generate_hash(word, global_salt, entry_salt, int(iterations), iv, ct), word)
