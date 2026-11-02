#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

# PBKDF1-SHA1: iterations of sha1 over the running digest, starting from pass.salt. Written
# PBKDF1:sha1:iter:base64(salt):base64(digest).


def module_constraints():
  return [[0, 256], [4, 100], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, salt_is_b64=False):
  iterations = 1000 if iterations is None else int(iterations)

  salt_dec = base64.b64decode(salt) if salt_is_b64 else salt.encode("latin-1")

  digest = word + salt_dec

  for _ in range(iterations):
    digest = hashlib.sha1(digest).digest()

  return "PBKDF1:sha1:%d:%s:%s" % (iterations, base64.b64encode(salt_dec).decode(), base64.b64encode(digest).decode())


def module_verify_hash(line):
  fields = line.split(b":", 5)

  if len(fields) != 6 or fields[0] != b"PBKDF1" or fields[1] != b"sha1":
    return None

  word = fields[5]

  try:
    salt = base64.b64decode(fields[3]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, fields[2].decode()), word)
