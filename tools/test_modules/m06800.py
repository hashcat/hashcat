#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, split_hash_word

# LastPass: PBKDF2-HMAC-SHA256 of the password over the e-mail salt, then AES-256-CBC of the first 16
# salt bytes.


def module_constraints():
  return [[0, 256], [10, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iv=None):
  iterations = 100100 if iterations is None else int(iterations)

  if iv is None:
    iv = random_bytes(16)

  key = hashlib.pbkdf2_hmac("sha256", word, salt.encode("latin-1"), iterations, 32)

  from Crypto.Util.Padding import pad

  enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(salt.encode("latin-1")[:16], 16))

  return "%s:%d:%s:%s" % (enc.hex()[:32], iterations, salt, iv.hex())


def module_verify_hash(line):
  parts = line.split(b":", 4)

  if len(parts) != 5:
    return None

  _, iterations, salt, iv, word = parts

  try:
    return (module_generate_hash(word, salt.decode(), iterations.decode(), bytes.fromhex(iv.decode())), word)
  except ValueError:
    return None
