#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# BestCrypt v3 volume. The key is SHA-256 of a 64 KiB buffer filled by repeating
# salt || password. A 64 byte plaintext and its SHA-256 are then AES-256-CBC
# encrypted (zero IV, no padding); a password is right when decrypting the stored
# data reproduces a block whose SHA-256 matches its trailing 32 bytes.

BUF_SIZE = 0x10000


def module_constraints():
  return [[0, 56], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, data=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  comb = salt + word
  length = len(comb)

  buf = b""

  for _ in range(0, BUF_SIZE, length):
    buf += comb

  buf = buf[:BUF_SIZE]

  key = hashlib.sha256(buf).digest()

  aes = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)

  if data is not None:  # decrypt
    plain_text = aes.decrypt(data)

    part1 = plain_text[0:64]
    part2 = plain_text[64:96]

    if hashlib.sha256(part1).digest() != part2:  # wrong -> fake the data
      data = b"\x00" * len(data)
  else:  # encrypt
    data = random_bytes(64)
    h = hashlib.sha256(data).digest()
    data = aes.encrypt(data + h)

  return "$bcve$3$08$%s$%s" % (salt.hex(), data.hex())


def module_verify_hash(line):
  idx1 = line.find(b":")

  if idx1 < 1:
    return None

  hash_in = line[:idx1].decode(errors="replace")
  word = line[idx1 + 1:]

  if hash_in[:8] != "$bcve$3$":
    return None

  idx1 = hash_in.find("$", 8)

  if idx1 < 1:
    return None

  crypto_type = hash_in[8:idx1]

  if crypto_type != "08":
    return None

  idx2 = hash_in.find("$", idx1 + 1)

  salt = hash_in[idx1 + 1:idx2]

  if not salt or any(c not in "0123456789abcdefABCDEF" for c in salt):
    return None

  data = hash_in[idx2 + 1:]

  if not data or any(c not in "0123456789abcdefABCDEF" for c in data):
    return None

  salt = bytes.fromhex(salt)
  data = bytes.fromhex(data)

  new_hash = module_generate_hash(word, salt, data)

  return (new_hash, word)
