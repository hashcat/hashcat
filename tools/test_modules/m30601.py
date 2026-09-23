#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac

from Crypto.Protocol.KDF import bcrypt

# bcrypt-sha256 v2 (passlib): the bcrypt password is the standard base64 of
# HMAC-SHA256(key=bcrypt_base64(salt), msg=word). pycryptodome emits a full $2a crypt string; its
# last 31 chars are the bcrypt-base64 of the 23 byte hash, which is what the format wants.

_STD2BC = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                        "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_BC2STD = str.maketrans("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def _en_base64(data):
  return base64.b64encode(data).decode().rstrip("=").translate(_STD2BC)


def _de_base64(text):
  std = text.translate(_BC2STD)

  return base64.b64decode(std + "=" * (-len(std) % 4))


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = "10" if iterations is None or iterations == "" else str(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  encoded_salt = _en_base64(salt_bytes)

  mac = hmac.new(encoded_salt.encode(), word, hashlib.sha256).digest()

  bcrypt_word = base64.b64encode(mac)

  full = bcrypt(bcrypt_word, int(cost), salt_bytes).decode()

  return "$bcrypt-sha256$v=2,t=2b,r=%s$%s$%s" % (cost, encoded_salt, full[-31:])


def module_verify_hash(line):
  idx = line.find(b":", 82)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  idx2 = hash_in.find("r=")

  if idx2 < 0:
    return None

  idx3 = hash_in.find("$", idx2)

  if idx3 < 0:
    return None

  iter = hash_in[idx2 + 2:idx3]

  salt = _de_base64(hash_in[idx3 + 1:idx3 + 23])

  return (module_generate_hash(word, salt, iter), word)
