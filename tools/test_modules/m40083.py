#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac
import re

from lib.test_helpers import random_bytes, random_number, split_hash_word

# Fernet with the key derived as sha256(pass): HMAC-SHA256 with the first 16 bytes of the key over
# the version byte 0x80, the timestamp, the IV and the ciphertext, all base64url encoded with the
# HMAC appended. Only the HMAC is checked, so the ciphertext is random bytes, 1 block for each
# character of the salt. A token is written with or without its padding.

TOKEN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def module_constraints():
  return [[0, 256], [1, 14], [-1, -1], [-1, -1], [-1, -1]]


def fernet_token(word, data, padded):
  key = hashlib.sha256(word).digest()

  sig = hmac.new(key[0:16], data, hashlib.sha256).digest()

  token = base64.urlsafe_b64encode(data + sig).decode()

  if padded == False:
    token = token.rstrip("=")

  return token


def module_generate_hash(word, salt, iterations=None):
  blocks = len(salt) if salt else 2

  data = b"\x80" + random_bytes(8) + random_bytes(16) + random_bytes(16 * blocks)

  return fernet_token(word, data, random_number(0, 1) == 1)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if TOKEN.match(hash_in) is None:
    return None

  b64 = hash_in.rstrip("=")

  try:
    raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
  except ValueError:
    return None

  if len(raw) < 73:
    return None

  return (fernet_token(word, raw[:-32], hash_in.endswith("=")), word)
