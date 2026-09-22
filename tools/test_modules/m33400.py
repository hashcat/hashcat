#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac

from lib.test_helpers import random_bytes, random_number

# mega.nz password protected link. The link body is base64url of
#
#   algorithm(1) || file/folder(1) || public handle(6) || salt(32) ||
#   encrypted key(16 for a folder, 32 for a file) || MAC tag(32)
#
# and what hashcat verifies is the MAC tag. The key is PBKDF2-HMAC-SHA512(password, salt, 100000)
# taken to 64 bytes: the first half decrypts the link key and the second half is the HMAC-SHA256
# key over everything ahead of the tag. Only algorithm 2 is parsed.
#
# The file/folder byte is picked at random per candidate so that both link lengths are exercised,
# since it decides whether the encrypted key is 16 or 32 bytes and therefore how much data the MAC
# covers.

ITERATIONS = 100000

ALGORITHM = 2
TAG_LEN   = 32
HEAD_LEN  = 1 + 1 + 6 + 32


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def _mac(word, salt_raw, data):
  dk = hashlib.pbkdf2_hmac("sha512", word, salt_raw, ITERATIONS, 64)

  return hmac.new(dk[32:], data, hashlib.sha256).digest()


def _build(data, mac):
  return "P!" + base64.urlsafe_b64encode(data + mac).decode("ascii").rstrip("=")


def module_generate_hash(word, salt, iterations=None):
  salt_raw = bytes.fromhex(salt)

  is_file = random_number(0, 1)

  data = bytes([ALGORITHM, is_file]) + random_bytes(6) + salt_raw + random_bytes(32 if is_file else 16)

  return _build(data, _mac(word, salt_raw, data))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  if not hash_in.startswith(b"P!"):
    return None

  body = hash_in[2:]

  try:
    raw = base64.urlsafe_b64decode(body + b"=" * ((4 - len(body) % 4) % 4))
  except Exception:
    return None

  if len(raw) not in (HEAD_LEN + 16 + TAG_LEN, HEAD_LEN + 32 + TAG_LEN):
    return None

  data, mac = raw[:-TAG_LEN], raw[-TAG_LEN:]

  if data[0] != ALGORITHM:
    return None

  if _mac(word, data[8:40], data) != mac:
    return None

  return (_build(data, mac), word)
