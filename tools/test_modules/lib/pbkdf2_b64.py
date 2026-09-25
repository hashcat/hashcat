#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The name:iterations:base64(salt):base64(key) PBKDF2 line, with the key as long as the line says.

import base64
import binascii
import hashlib


def generate_hash(name, algo, word, salt, iterations, out_len):
  salt_bytes = salt.encode("latin-1")

  raw = hashlib.pbkdf2_hmac(algo, word, salt_bytes, iterations, out_len)

  return "%s:%d:%s:%s" % (name, iterations, base64.b64encode(salt_bytes).decode(), base64.b64encode(raw).decode())


def parse(name, line):
  # (salt, iterations, key length, word); the password is after the last colon, so it cannot hold
  # one

  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split(":")

  if len(data) != 4 or data[0] != name or not data[1].isdigit():
    return None

  try:
    salt = base64.b64decode(data[2]).decode("latin-1")
    out_len = len(base64.b64decode(data[3]))
  except binascii.Error:
    return None

  return (salt, int(data[1]), out_len, word)
