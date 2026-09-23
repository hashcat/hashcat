#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# Teamspeak 3 (channel hash): SHA-1 over the base64 of SHA-1 of the password and the base64 of the
# 112 byte salt.


def module_constraints():
  return [[0, 256], [224, 224], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_b64 = base64.b64encode(bytes.fromhex(salt))

  digest = hashlib.sha1(base64.b64encode(hashlib.sha1(word).digest()) + salt_b64).digest()

  return "$teamspeak$3$%s$%s" % (base64.b64encode(digest).decode(), salt_b64.decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) < 5:
    return None

  try:
    return (module_generate_hash(word, base64.b64decode(data[4]).hex()), word)
  except binascii.Error:
    return None
