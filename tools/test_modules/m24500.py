#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# Telegram Desktop >= 2.1.14. PBKDF2-HMAC-SHA512 over the salt derives a 136 byte auth key. From it
# and the message key a per message AES-256 key and IV are built, and the message is AES-IGE
# en/decrypted. AES-IGE is not in a stdlib, so it is done on top of ECB.

BLOCK = 16


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a[:BLOCK], b[:BLOCK]))


def aes256_encrypt_ige(key, iv, data):
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


def aes256_decrypt_ige(key, iv, data):
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
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  iterations = 100000 if iterations is None else int(iterations)

  sha512_hash = hashlib.sha512(salt + word + salt).digest()

  authkey = hashlib.pbkdf2_hmac("sha512", sha512_hash, salt, iterations, 136)

  if data is not None:
    message = data[16:]
    message_key = data[0:16]
  else:
    message = random_bytes(272)
    message_key = hashlib.sha1(message).digest()[0:16]

  data_a = bytearray(48)
  data_b = bytearray(48)
  data_c = bytearray(48)
  data_d = bytearray(48)

  data_a[0:16] = message_key
  data_b[16:32] = message_key
  data_c[32:48] = message_key
  data_d[0:16] = message_key

  data_a[16:48] = authkey[8:40]
  data_b[0:16] = authkey[40:56]
  data_b[32:48] = authkey[56:72]
  data_c[0:32] = authkey[72:104]
  data_d[16:48] = authkey[104:136]

  sha1_a = hashlib.sha1(bytes(data_a)).digest()
  sha1_b = hashlib.sha1(bytes(data_b)).digest()
  sha1_c = hashlib.sha1(bytes(data_c)).digest()
  sha1_d = hashlib.sha1(bytes(data_d)).digest()

  aes_key = sha1_a[0:8] + sha1_b[8:20] + sha1_c[4:16]

  aes_iv = sha1_a[8:20] + sha1_b[0:8] + sha1_c[16:20] + sha1_d[0:8]

  enc_data = b""

  if data is not None:
    dec_data = aes256_decrypt_ige(aes_key, aes_iv, message)

    if hashlib.sha1(dec_data).digest()[0:16] == message_key:
      enc_data = data
  else:
    enc_data = message_key + aes256_encrypt_ige(aes_key, aes_iv, message)

  return "$telegram$2*%i*%s*%s" % (iterations, salt.hex(), enc_data.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[0:10] != "$telegram$":
    return None

  if hash_in[10:11] != "2":
    return None

  fields = hash_in.split("*")

  if len(fields) != 4:
    return None

  _, iterations, salt, data = fields

  if len(salt) != 64 or len(data) != 576:
    return None

  if not iterations.isdigit() or iterations[0] == "0":
    return None

  new_hash = module_generate_hash(word, bytes.fromhex(salt), iterations, bytes.fromhex(data))

  return (new_hash, word)
