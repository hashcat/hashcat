#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The passlib PBKDF2 line, $prefix$iterations$salt$key, both in base64 with . for + and no padding.

import base64
import binascii
import hashlib

from lib.test_helpers import random_bytes


def ab64(data):
  return base64.b64encode(data).decode().replace("+", ".").rstrip("=")


def ab64_decode(text):
  return base64.b64decode(text.replace(".", "+") + "=" * (-len(text) % 4))


def generate_hash(prefix, algo, word, salt, iterations):
  iterations = 1024 if iterations is None else int(iterations)

  if salt is None:
    salt = random_bytes(16)

  key = hashlib.pbkdf2_hmac(algo, word, salt, iterations)

  return "%s%d$%s$%s" % (prefix, iterations, ab64(salt), ab64(key))


def verify_hash(prefix, algo, line):
  if not line.startswith(prefix.encode()):
    return None

  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in[len(prefix):].split("$")

  if len(data) < 3 or not data[0].isdigit():
    return None

  try:
    salt = ab64_decode(data[1])
  except binascii.Error:
    return None

  return (generate_hash(prefix, algo, word, salt, data[0]), word)
