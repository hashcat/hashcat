#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_salt_word

# RSA Security Analytics / NetWitness (sha256): upper case hex of
# sha256(strtoupper(sha256($pass)).$salt), the salt in base64 after it.


def module_constraints():
  return [[0, 256], [0, 256], [0, 55], [0, 51], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  inner = hashlib.sha256(word).hexdigest().upper().encode()

  digest = hashlib.sha256(inner + salt_bytes).hexdigest().upper()

  return "%s:%s" % (digest, base64.b64encode(salt_bytes).decode())


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt_b64, word = parts

  try:
    salt = base64.b64decode(salt_b64).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt), word)
