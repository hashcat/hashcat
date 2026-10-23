#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, kernel_charset, utf16be, test_iteration_parameters


def module_reduced_iteration_constraints():
  return {
    'parameters': {'n': (1024, 2048, 'power2')},
    'compiled_cost': True,
  }


# Bisq wallet. The key is scrypt over the UTF-16BE password and the stored salt. A single
# AES-256-CBC block holds a fixed marker (16 bytes of 0x10); the real password decrypts it back to
# that marker. Verify keeps the block only when it decrypts to the marker.

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 6

DATA_FIXED = b"\x10" * 16


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects this module's reduced parameters.
ITERATION_PARAMETERS = test_iteration_parameters(29800)


def _derive_key(word, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
  word_utf16be = utf16be(word, kernel_charset())

  return hashlib.scrypt(word_utf16be, salt=salt, n=n, r=r, p=p,
                        dklen=32, maxmem=1024 * 1024 * 1024)


def module_constraints():
  return [[8, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, data=None, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if iv is None:
    iv = random_bytes(16)

  key = _derive_key(word, salt, n, r, p)

  aes_cbc = AES.new(key, AES.MODE_CBC, iv)

  data_block = b""

  if data is not None:
    data_dec = aes_cbc.decrypt(data)

    if data_dec == DATA_FIXED:
      data_block = data
  else:
    data_block = aes_cbc.encrypt(DATA_FIXED)

  return "$bisq$3*%d*%d*%d*%s*%s" % (n, r, p, salt.hex(), (iv + data_block).hex())


def module_verify_hash(line):
  if line[0:8] != b"$bisq$3*":
    return None

  idx1 = line.find(b":", 12)

  if idx1 < 1:
    return None

  hash_in = line[:idx1].decode(errors="replace")
  word = line[idx1 + 1:]

  fields = hash_in.split("*")

  if len(fields) != 6:
    return None

  salt = fields[4]
  iv = fields[5][:32]
  data = fields[5][32:64]

  if len(salt) != 16 or any(c not in "0123456789abcdefABCDEF" for c in salt):
    return None

  if len(iv) != 32 or any(c not in "0123456789abcdefABCDEF" for c in iv):
    return None

  if len(data) != 32 or any(c not in "0123456789abcdefABCDEF" for c in data):
    return None

  new_hash = module_generate_hash(word, bytes.fromhex(salt), bytes.fromhex(iv), bytes.fromhex(data), int(fields[1]), int(fields[2]), int(fields[3]))

  return (new_hash, word)
