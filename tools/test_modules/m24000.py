#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lib.pyserpent import Serpent
from lib.pytwofish import Twofish
from lib.test_helpers import random_bytes, random_number

# BestCrypt v4 volume. The key is scrypt (N=32768, r=16, p=1) of the password
# salted, and the 64 byte plaintext plus its SHA-256 is encrypted in CBC (zero IV,
# no padding) under one of four ciphers: 0x08 AES, 0x09 Twofish, 0x0a Serpent,
# 0x0f Camellia. A password is right when decrypting reproduces a block whose
# SHA-256 matches its trailing 32 bytes.

SCRYPT_N = 32768
SCRYPT_R = 16
SCRYPT_P = 1

CRYPTO_TYPE_CONV = (8, 9, 10, 15)


def module_constraints():
  return [[0, 256], [24, 24], [-1, -1], [-1, -1], [-1, -1]]


def _cbc_encrypt(block_encrypt, data, iv):
  out = b""
  prev = iv

  for i in range(0, len(data), 16):
    enc = block_encrypt(strxor(data[i:i + 16], prev))
    out += enc
    prev = enc

  return out


def _cbc_decrypt(block_decrypt, data, iv):
  out = b""
  prev = iv

  for i in range(0, len(data), 16):
    blk = data[i:i + 16]
    out += strxor(block_decrypt(blk), prev)
    prev = blk

  return out


def _encrypt(type, key, data):
  iv = b"\x00" * 16

  if type == 8:
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)
  if type == 9:
    return _cbc_encrypt(Twofish(key).encrypt, data, iv)
  if type == 10:
    return _cbc_encrypt(Serpent(key).encrypt, data, iv)
  # type == 15, Camellia
  enc = Cipher(algorithms.Camellia(key), modes.CBC(iv)).encryptor()
  return enc.update(data) + enc.finalize()


def _decrypt(type, key, data):
  iv = b"\x00" * 16

  if type == 8:
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)
  if type == 9:
    return _cbc_decrypt(Twofish(key).decrypt, data, iv)
  if type == 10:
    return _cbc_decrypt(Serpent(key).decrypt, data, iv)
  # type == 15, Camellia
  dec = Cipher(algorithms.Camellia(key), modes.CBC(iv)).decryptor()
  return dec.update(data) + dec.finalize()


def module_generate_hash(word, salt, data=None, type=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  # most heavy part of the algorithm
  maxmem = 128 * SCRYPT_N * SCRYPT_R * 2
  key = hashlib.scrypt(word, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                       dklen=32, maxmem=maxmem)

  if type is None:
    type = CRYPTO_TYPE_CONV[random_number(0, 3)]

  if data is not None:  # decrypt
    plain_text = _decrypt(type, key, data)

    part1 = plain_text[0:64]
    part2 = plain_text[64:96]

    if hashlib.sha256(part1).digest() != part2:  # wrong -> fake the data
      data = b"\x00" * len(data)
  else:  # encrypt
    data = random_bytes(64)
    h = hashlib.sha256(data).digest()
    data = _encrypt(type, key, data + h)

  return "$bcve$4$%02x$%s$%s" % (type, salt.hex(), data.hex())


def module_verify_hash(line):
  idx1 = line.find(b":")

  if idx1 < 1:
    return None

  hash_in = line[:idx1].decode(errors="replace")
  word = line[idx1 + 1:]

  if hash_in[:8] != "$bcve$4$":
    return None

  idx1 = hash_in.find("$", 8)

  if idx1 < 1:
    return None

  crypto_type = hash_in[8:idx1]

  if crypto_type not in ("08", "09", "0a", "0f"):
    return None

  crypto_type = int(crypto_type, 16)

  idx2 = hash_in.find("$", idx1 + 1)

  salt = hash_in[idx1 + 1:idx2]

  if not salt or any(c not in "0123456789abcdefABCDEF" for c in salt):
    return None

  data = hash_in[idx2 + 1:]

  if not data or any(c not in "0123456789abcdefABCDEF" for c in data):
    return None

  salt = bytes.fromhex(salt)
  data = bytes.fromhex(data)

  new_hash = module_generate_hash(word, salt, data, crypto_type)

  return (new_hash, word)
