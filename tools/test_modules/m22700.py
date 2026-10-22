#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number, kernel_charset, utf16be

# MultiBit HD v2. The key is scrypt over the UTF-16BE password and a fixed salt. Two AES-256-CBC
# blocks may carry the wallet marker; the real one decrypts to a bitcoinj header that starts with
# "\norg." followed by lowercase package characters. Verify tries block 1 with the file IV, then
# block 2 with a fixed IV, and keeps the fields when either decrypts to that marker.

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1

FIXED_SALT = bytes.fromhex("3551038075a3b0c5")
FIXED_IV   = bytes.fromhex("a344391f538311b329548616c489723e")

BITCOINJ_CHARS = ".abcdefghijklmnopqrstuvwxyz"


def _verify_bitcoinj(data):
  if data[0:1] != b"\n":
    return False

  if data[1] >= 128:
    return False

  if data[2:6] != b"org.":
    return False

  for i in range(6, 14):
    if chr(data[i]) not in BITCOINJ_CHARS:
      return False

  return True


def _derive_key(word):
  word_utf16be = utf16be(word, kernel_charset())

  return hashlib.scrypt(word_utf16be, salt=FIXED_SALT, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=32, maxmem=128 * 1024 * 1024)


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, iv, block1=None, block2=None):
  if isinstance(iv, str):
    iv = iv.encode("latin-1")

  key = _derive_key(word)

  data_block1 = b""
  data_block2 = b""

  if block1 is not None:
    data_dec = AES.new(key, AES.MODE_CBC, iv).decrypt(block1)

    if _verify_bitcoinj(data_dec):
      data_block1 = block1
      data_block2 = block2
    else:
      data_dec = AES.new(key, AES.MODE_CBC, FIXED_IV).decrypt(block2)

      if _verify_bitcoinj(data_dec):
        data_block1 = block1
        data_block2 = block2
  else:
    data = bytearray()

    data += b"\n"
    data.append(random_number(0, 127))
    data += b"org."

    for _ in range(6, 16):
      data.append(ord(BITCOINJ_CHARS[random_number(0, len(BITCOINJ_CHARS) - 1)]))

    random_alternative = random_number(0, 1)

    if random_alternative == 0:
      data_block1 = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes(data))
      data_block2 = iv  # fake
    else:
      data_block1 = iv  # fake
      data_block2 = AES.new(key, AES.MODE_CBC, FIXED_IV).encrypt(bytes(data))

  return "$multibit$2*%s*%s*%s" % (iv.hex(), data_block1.hex(), data_block2.hex())


def module_verify_hash(line):
  if line[0:12] != b"$multibit$2*":
    return None

  idx = line.find(b":", 12)

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  # $multibit$2*<iv>*<block1>*<block2>
  fields = hash_in.split("*")

  if len(fields) != 4:
    return None

  iv, block1, block2 = fields[1], fields[2], fields[3]

  for field in (iv, block1, block2):
    if len(field) != 32 or any(c not in "0123456789abcdefABCDEF" for c in field):
      return None

  new_hash = module_generate_hash(word, bytes.fromhex(iv), bytes.fromhex(block1), bytes.fromhex(block2))

  return (new_hash, word)
