#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# Telegram Desktop <= 2.1.13. PBKDF2-HMAC-SHA1 makes a 136 byte authkey, whose bytes are scattered
# into four SHA1 inputs together with the message key to derive an AES-256 key and IV. The payload is
# AES-256 in IGE mode, which is built here from ECB.

BLOCK = 16


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def _ige_encrypt(key, iv, data):
  ecb = AES.new(key, AES.MODE_ECB)

  x_prev = iv[BLOCK:2 * BLOCK]
  y_prev = iv[0:BLOCK]

  out = b""

  for i in range(0, len(data), BLOCK):
    x = data[i:i + BLOCK]
    y = _xor(ecb.encrypt(_xor(x, y_prev)), x_prev)
    x_prev = x
    y_prev = y
    out += y

  return out


def _ige_decrypt(key, iv, data):
  ecb = AES.new(key, AES.MODE_ECB)

  x_prev = iv[0:BLOCK]
  y_prev = iv[BLOCK:2 * BLOCK]

  out = b""

  for i in range(0, len(data), BLOCK):
    x = data[i:i + BLOCK]
    y = _xor(ecb.decrypt(_xor(x, y_prev)), x_prev)
    x_prev = x
    y_prev = y
    out += y

  return out


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, data=None):
  iters = 4000 if iterations is None else int(iterations)

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  authkey = hashlib.pbkdf2_hmac("sha1", word, salt, iters, 136)

  if data is not None:
    message     = data[16:]
    message_key = data[0:16]
  else:
    message     = random_bytes(272)
    message_key = hashlib.sha1(message).digest()[0:16]

  data_a = bytearray(48)
  data_b = bytearray(48)
  data_c = bytearray(48)
  data_d = bytearray(48)

  data_a[0:16]  = message_key
  data_b[16:32] = message_key
  data_c[32:48] = message_key
  data_d[0:16]  = message_key

  data_a[16:48] = authkey[8:40]
  data_b[0:16]  = authkey[40:56]
  data_b[32:48] = authkey[56:72]
  data_c[0:32]  = authkey[72:104]
  data_d[16:48] = authkey[104:136]

  sha1_a = hashlib.sha1(bytes(data_a)).digest()
  sha1_b = hashlib.sha1(bytes(data_b)).digest()
  sha1_c = hashlib.sha1(bytes(data_c)).digest()
  sha1_d = hashlib.sha1(bytes(data_d)).digest()

  aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]
  aes_iv  = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]

  enc_data = b""

  if data is not None:
    dec_data = _ige_decrypt(aes_key, aes_iv, message)

    if hashlib.sha1(dec_data).digest()[0:16] == message_key:
      enc_data = data
  else:
    enc_data = message_key + _ige_encrypt(aes_key, aes_iv, message)

  return "$telegram$1*%d*%s*%s" % (iters, salt.hex(), enc_data.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[0:10] != "$telegram$":
    return None

  if hash_in[10:11] != "1":
    return None

  fields = hash_in.split("*")

  if len(fields) != 4:
    return None

  iters, salt, data = fields[1], fields[2], fields[3]

  if len(salt) != 64 or len(data) != 576:
    return None

  return (module_generate_hash(word, bytes.fromhex(salt), int(iters), bytes.fromhex(data)), word)
