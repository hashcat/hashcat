#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# 1Password agilekeychain: PBKDF2-HMAC-SHA1 of the password over the 8 byte salt, then AES-128-CBC of
# a fixed block. The line packs the salt hex, a 1008 byte prefix and the IV together.


def get_random_salt():
  return (random_bytes(8) + b"\x00" * 1008 + random_bytes(16)).hex()


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 1000 if iterations is None else int(iterations)

  if not salt:
    salt = get_random_salt()

  salt_hex = salt[:16]
  prefix = salt[16:2032]
  iv_hex = salt[2032:]

  key = __import__("hashlib").pbkdf2_hmac("sha1", word, bytes.fromhex(salt_hex), iterations, 16)

  enc = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex)).encrypt(bytes.fromhex("10" * 16))

  return "%d:%s:%s%s%s" % (iterations, salt_hex, prefix, iv_hex, enc.hex()[:32])


def module_verify_hash(line):
  if line.count(b":") < 3:
    return None

  i1 = line.find(b":")
  iterations = line[:i1].decode()

  i2 = line.find(b":", i1 + 1)
  salt = line[i1 + 1:i2].decode()

  i3 = line.find(b":", i2 + 1)

  salt += line[i2 + 1:i3 - 32].decode()

  word = line[i3 + 1:]

  try:
    return (module_generate_hash(word, salt, iterations), word)
  except ValueError:
    return None
