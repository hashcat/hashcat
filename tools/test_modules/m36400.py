#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import Blowfish

from lib.test_helpers import random_bytes, split_hash_word

# KWallet 5, PBKDF2-HMAC-SHA512 into a 56 byte Blowfish key, CBC over the 64 byte header. KDE byte
# swaps every 32 bit word of the file before it reaches Blowfish, a bug the on disk format is stuck
# with, so the swap is undone before decrypting and redone after encrypting.


def kwallet_alter_endianity(data):
  return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


def kwallet_random_plain(ct_len):
  # 8 byte random block that is also the CBC IV, the payload size stored reversed, then 52 byte of
  # payload whose every third byte is zeroed so the reader accepts the key.

  payload = bytearray(random_bytes(52))

  for i in range(0, 52, 3):
    payload[i] = 0

  head = random_bytes(8)

  size = (ct_len - 12).to_bytes(4, "big")[::-1]

  return (head + size + bytes(payload)).hex()


def module_constraints():
  return [[0, 256], [112, 112], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, ct_len=88, plain=None):
  iterations = 50000 if iterations is None else int(iterations)
  ct_len     = int(ct_len)

  if plain is None:
    plain = kwallet_random_plain(ct_len)

  plain  = bytes.fromhex(plain)
  b_salt = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha512", word, b_salt, iterations, 56)

  iv = plain[0:8]

  ct_sw = iv + Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(plain[8:8 + 56])

  ct = kwallet_alter_endianity(ct_sw)

  return "$kwallet$%d$%s$1$%d$%s$%d" % (ct_len, ct.hex(), len(b_salt), salt, iterations)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 8:
    return None

  _, signature, ct_len, ct, minor, salt_len, salt, iterations = data

  if signature != "kwallet" or minor != "1":
    return None

  if len(ct) != 128 or len(salt) != int(salt_len) * 2:
    return None

  b_salt = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha512", word, b_salt, int(iterations), 56)

  ct_sw = kwallet_alter_endianity(bytes.fromhex(ct))

  iv = ct_sw[0:8]

  plain = iv + Blowfish.new(key, Blowfish.MODE_CBC, iv).decrypt(ct_sw[8:8 + 56])

  new_hash = module_generate_hash(word, salt, iterations, ct_len, plain.hex())

  return (new_hash, word)
