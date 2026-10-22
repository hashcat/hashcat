#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# Stellar wallet: PBKDF2-HMAC-SHA256 of the password over a 16 byte salt, then AES-GCM. The line is
# the salt, the 12 byte nonce and the ciphertext with its 16 byte tag, each base64 encoded.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, ct=None):
  if iv is None:
    iv = random_hex_string(24)

  salt_bin = bytes.fromhex(salt)
  iv_bin = bytes.fromhex(iv)

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bin, 4096, 32)

  if ct is not None:
    ct_bin = bytes.fromhex(ct)

    data_bin = ct_bin[:-16]
    tag_bin = ct_bin[-16:]

    aes = AES.new(key, AES.MODE_GCM, nonce=iv_bin)

    pt = aes.decrypt(data_bin)

    try:
      aes.verify(tag_bin)
    except ValueError:
      pt = b"\xff" * 56
  else:
    pt = b"\xff" * 56

  aes = AES.new(key, AES.MODE_GCM, nonce=iv_bin)

  ct_bin, tag_bin = aes.encrypt_and_digest(pt)

  return "$stellar$%s$%s$%s" % (
    base64.b64encode(salt_bin).decode("ascii"),
    base64.b64encode(iv_bin).decode("ascii"),
    base64.b64encode(ct_bin + tag_bin).decode("ascii"))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[:9] != "$stellar$":
    return None

  parts = hash_in.split("$")

  if len(parts) < 5:
    return None

  salt, iv, ct = parts[2], parts[3], parts[4]

  try:
    salt_bin = base64.b64decode(salt)
    iv_bin = base64.b64decode(iv)
    ct_bin = base64.b64decode(ct)
  except Exception:
    return None

  if len(salt_bin) != 16 or len(iv_bin) != 12 or len(ct_bin) != 72:
    return None

  return (module_generate_hash(word, salt_bin.hex(), iv_bin.hex(), ct_bin.hex()), word)
