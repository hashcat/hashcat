#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, kernel_charset, utf16be

# MultiBit Classic (.key). The key is scrypt over the UTF-16BE password and an 8 byte salt. A
# single AES-256-CBC block carries a fixed 16 byte marker of 0x10 octets, which is what the pure
# and optimized kernels disagree on for a multi byte password: latin-1 widens each byte, utf-8
# decodes it. kernel_charset () follows the family test.sh is about to run.

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1

DATA_FIXED = b"\x10" * 16


def module_constraints():
  return [[0, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def _derive_key(word, salt):
  word_utf16be = utf16be(word, kernel_charset())

  return hashlib.scrypt(word_utf16be, salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=32, maxmem=128 * 1024 * 1024)


def module_generate_hash(word, salt, iv=None, data=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if iv is None:
    iv = random_bytes(16)

  key = _derive_key(word, salt)

  data_block = b""

  if data is not None:
    data_dec = AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    if data_dec == DATA_FIXED:
      data_block = data
  else:
    data_block = AES.new(key, AES.MODE_CBC, iv).encrypt(DATA_FIXED)

  return "$multibit$3*%d*%d*%d*%s*%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P,
                                         salt.hex(), (iv + data_block).hex())


def module_verify_hash(line):
  if line[0:12] != b"$multibit$3*":
    return None

  idx = line.find(b":", 12)

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  # $multibit$3*N*R*P*<salt>*<iv||data>
  fields = hash_in.split("*")

  if len(fields) != 6:
    return None

  salt = fields[4]
  iv   = fields[5][:32]
  data = fields[5][32:32 + 32]

  hexset = "0123456789abcdefABCDEF"

  if len(salt) != 16 or any(c not in hexset for c in salt):
    return None

  if len(iv) != 32 or any(c not in hexset for c in iv):
    return None

  if len(data) != 32 or any(c not in hexset for c in data):
    return None

  new_hash = module_generate_hash(word, bytes.fromhex(salt), bytes.fromhex(iv), bytes.fromhex(data))

  return (new_hash, word)
