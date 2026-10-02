#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import split_hash_word

# EPiServer 6.x (v4): SHA256 over the salt and the password widened to UTF-16LE byte by
# byte, both base64 encoded, the digest cut to 43 characters.


def module_constraints():
  return [[0, 256], [0, 256], [0, 27], [0, 27], [0, 27]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  digest = hashlib.sha256(salt_bytes + word.decode("latin-1").encode("utf-16-le")).digest()

  return "$episerver$*1*%s*%s" % (base64.b64encode(salt_bytes).decode(), base64.b64encode(digest).decode()[:43])


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in[14:].split("*")

  if len(fields) < 2:
    return None

  try:
    salt = base64.b64decode(fields[0]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt), word)
