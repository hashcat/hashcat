#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import RIPEMD160

from lib.test_helpers import random_number, split_hash_word

# BIP38 without EC multiply. The key is scrypt (pass, addresshash, N = 16384, r = 8, p = 8) of 64
# bytes, and AES-256 under its second half encrypts the private key xor its first half, 16 bytes at a
# time. The addresshash is the first 4 bytes of sha256 (sha256 (address)) of the key's P2PKH address,
# so a password is verified by decrypting, deriving the address and hashing it again.

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 8

P  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def point_add(p1, p2):
  if p1 is None:
    return p2

  if p2 is None:
    return p1

  if (p1[0] == p2[0]) and (p1[1] != p2[1]):
    return None

  if p1 == p2:
    lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
  else:
    lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P

  x = (lam * lam - p1[0] - p2[0]) % P
  y = (lam * (p1[0] - x) - p1[1]) % P

  return (x, y)


def point_mul(k):
  result = None
  addend = (GX, GY)

  while k > 0:
    if (k & 1) == 1:
      result = point_add(result, addend)

    addend = point_add(addend, addend)

    k >>= 1

  return result


def sha256d(data):
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58check_enc(payload):
  data = payload + sha256d(payload)[0:4]

  n = int.from_bytes(data, "big")

  out = ""

  while n > 0:
    n, r = divmod(n, 58)

    out = B58[r] + out

  for byte in data:
    if byte != 0:
      break

    out = "1" + out

  return out


def b58check_dec(text):
  n = 0

  for c in text:
    idx = B58.find(c)

    if idx < 0:
      return None

    n = n * 58 + idx

  data = n.to_bytes((n.bit_length() + 7) // 8, "big")

  pad = len(text) - len(text.lstrip("1"))

  data = bytes(pad) + data

  if len(data) < 5:
    return None

  if sha256d(data[:-4])[0:4] != data[-4:]:
    return None

  return data[:-4]


def address_of(prv, compressed):
  x, y = point_mul(int.from_bytes(prv, "big"))

  if compressed == True:
    pub = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
  else:
    pub = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

  h160 = RIPEMD160.new(hashlib.sha256(pub).digest()).digest()

  address = b58check_enc(b"\x00" + h160)

  return address


def bip38_encrypt(word, prv, compressed):
  address = address_of(prv, compressed)

  addresshash = sha256d(address.encode())[0:4]

  derived = hashlib.scrypt(word, salt=addresshash, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=256 * 1024 * 1024, dklen=64)

  aes = AES.new(derived[32:64], AES.MODE_ECB)

  eh1 = aes.encrypt(bytes(a ^ b for a, b in zip(prv[ 0:16], derived[ 0:16])))
  eh2 = aes.encrypt(bytes(a ^ b for a, b in zip(prv[16:32], derived[16:32])))

  flag = 0xe0 if compressed == True else 0xc0

  line = b58check_enc(bytes([0x01, 0x42, flag]) + addresshash + eh1 + eh2)

  return line


def bip38_decrypt(word, line):
  payload = b58check_dec(line)

  if payload is None:
    return None

  if len(payload) != 39:
    return None

  if payload[0:2] != b"\x01\x42":
    return None

  flag = payload[2]

  compressed = (flag & 0x20) == 0x20

  addresshash = payload[3:7]

  derived = hashlib.scrypt(word, salt=addresshash, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=256 * 1024 * 1024, dklen=64)

  aes = AES.new(derived[32:64], AES.MODE_ECB)

  prv = bytes(a ^ b for a, b in zip(aes.decrypt(payload[7:23]) + aes.decrypt(payload[23:39]), derived[0:32]))

  key = int.from_bytes(prv, "big")

  if key == 0:
    return None

  if key >= N:
    return None

  if sha256d(address_of(prv, compressed).encode())[0:4] != addresshash:
    return None

  return prv


def module_generate_hash(word, salt, prv=None, compressed=None):
  # test.py hands every mode a salt, and here it only seeds the private key, which the line then
  # carries encrypted, so the same word and salt always give the same line

  if prv is None:
    seed = salt.encode("latin-1") if isinstance(salt, str) else salt

    key = (int.from_bytes(hashlib.sha256(b"bip38" + seed).digest(), "big") % (N - 1)) + 1

    prv = key.to_bytes(32, "big")

  if compressed is None:
    compressed = random_number(0, 1) == 1

  line = bip38_encrypt(word, prv, compressed)

  return line


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  prv = bip38_decrypt(word, hash_in)

  if prv is None:
    return None

  payload = b58check_dec(hash_in)

  compressed = (payload[2] & 0x20) == 0x20

  line_out = bip38_encrypt(word, prv, compressed)

  return (line_out, word)
