#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import random

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# MetaMask: PBKDF2-HMAC-SHA256 of the password over a 32 byte salt, then AES-GCM. The line is the
# salt, the 16 byte nonce and the ciphertext with its 16 byte tag, each base64 encoded. When there
# is no ciphertext to decrypt the plaintext is a random length run of 0xff, so a generated hash is
# not reproducible from a seed and only the cross verification is meaningful here. The length is
# capped 16 bytes below CT_MAX_LEN so the ciphertext plus its tag still fits what verify accepts;
# the perl oracle does not cap and can emit a hash its own verify then rejects.

CT_MIN_LEN = 30
CT_MAX_LEN = 3136


def module_constraints():
  return [[8, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, ct=None):
  if iv is None:
    iv = random_hex_string(32)

  salt_bin = bytes.fromhex(salt)
  iv_bin = bytes.fromhex(iv)

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bin, 10000, 32)

  if ct is not None:
    ct_bin = bytes.fromhex(ct)

    data_bin = ct_bin[:-16]
    tag_bin = ct_bin[-16:]

    aes = AES.new(key, AES.MODE_GCM, nonce=iv_bin)

    pt = aes.decrypt(data_bin)

    try:
      aes.verify(tag_bin)
    except ValueError:
      pt = b"\xff" * (CT_MIN_LEN + int(random.random() * (CT_MAX_LEN - 16 - CT_MIN_LEN)) + 1)
  else:
    pt = b"\xff" * (CT_MIN_LEN + int(random.random() * (CT_MAX_LEN - 16 - CT_MIN_LEN)) + 1)

  aes = AES.new(key, AES.MODE_GCM, nonce=iv_bin)

  ct_bin, tag_bin = aes.encrypt_and_digest(pt)

  return "$metamask$%s$%s$%s" % (
    base64.b64encode(salt_bin).decode("ascii"),
    base64.b64encode(iv_bin).decode("ascii"),
    base64.b64encode(ct_bin + tag_bin).decode("ascii"))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[:10] != "$metamask$":
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

  if len(salt_bin) != 32 or len(iv_bin) != 16:
    return None

  if not (CT_MIN_LEN <= len(ct_bin) <= CT_MAX_LEN):
    return None

  return (module_generate_hash(word, salt_bin.hex(), iv_bin.hex(), ct_bin.hex()), word)
