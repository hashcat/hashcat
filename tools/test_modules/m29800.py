#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, kernel_charset, utf16be

# Bisq wallet. The key is scrypt over the UTF-16BE password and the stored salt. A single
# AES-256-CBC block holds a fixed marker (16 bytes of 0x10); the real password decrypts it back to
# that marker. Verify keeps the block only when it decrypts to the marker.

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 6

DATA_FIXED = b"\x10" * 16


def _derive_key(word, salt):
  word_utf16be = utf16be(word, kernel_charset())

  return hashlib.scrypt(word_utf16be, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        dklen=32, maxmem=1024 * 1024 * 1024)


def module_constraints():
  return [[8, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, data=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if iv is None:
    iv = random_bytes(16)

  key = _derive_key(word, salt)

  aes_cbc = AES.new(key, AES.MODE_CBC, iv)

  data_block = b""

  if data is not None:
    data_dec = aes_cbc.decrypt(data)

    if data_dec == DATA_FIXED:
      data_block = data
  else:
    data_block = aes_cbc.encrypt(DATA_FIXED)

  return "$bisq$3*%d*%d*%d*%s*%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), (iv + data_block).hex())


def module_verify_hash(line):
  if line[0:8] != b"$bisq$3*":
    return None

  idx1 = line.find(b":", 12)

  if idx1 < 1:
    return None

  hash_in = line[:idx1].decode(errors="replace")
  word = line[idx1 + 1:]

  # $bisq$3*<n>*<r>*<p>*<salt>*<iv+data>
  idx2 = hash_in.find("*", 12)

  if idx2 < 0:
    return None

  idx1 = hash_in.find("*", idx2 + 1)

  if idx1 < 0:
    return None

  idx2 = hash_in.find("*", idx1 + 1)

  if idx2 < 0:
    return None

  idx1 = hash_in.find("*", idx2 + 1)

  if idx1 < 0:
    return None

  salt = hash_in[idx2 + 1:idx1]

  iv = hash_in[idx1 + 1:idx1 + 1 + 32]
  data = hash_in[idx1 + 1 + 32:idx1 + 1 + 32 + 32]

  if len(salt) != 16 or any(c not in "0123456789abcdefABCDEF" for c in salt):
    return None

  if len(iv) != 32 or any(c not in "0123456789abcdefABCDEF" for c in iv):
    return None

  if len(data) != 32 or any(c not in "0123456789abcdefABCDEF" for c in data):
    return None

  new_hash = module_generate_hash(word, bytes.fromhex(salt), bytes.fromhex(iv), bytes.fromhex(data))

  return (new_hash, word)
