#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# SolarWinds Serv-U: SHA-512 of a 1024 byte PBKDF2-HMAC-SHA1 key, the 16 byte salt in base64.


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bytes, 1000, 1024)

  return "$solarwinds$1$%s$%s" % (base64.b64encode(salt_bytes).decode(), base64.b64encode(hashlib.sha512(key).digest()).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 5 or data[1] != "solarwinds" or data[2] != "1" or len(data[3]) != 24 or len(data[4]) != 88:
    return None

  try:
    salt = base64.b64decode(data[3]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt), word)
