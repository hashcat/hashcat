#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

# PBKDF2-HMAC-SHA256: sha256:iterations:base64(salt):base64(digest), the digest as long as the
# line says, 24 bytes by default.


def module_constraints():
  return [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, out_len=24):
  iterations = 1000 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  raw = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, out_len)

  return "sha256:%d:%s:%s" % (iterations, base64.b64encode(salt_bytes).decode(), base64.b64encode(raw).decode())


def module_verify_hash(line):
  # the password is after the last colon, so it cannot hold one

  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split(":")

  if len(data) != 4 or data[0] != "sha256" or not data[1].isdigit():
    return None

  try:
    salt = base64.b64decode(data[2]).decode("latin-1")
    out_len = len(base64.b64decode(data[3]))
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, int(data[1]), out_len), word)
