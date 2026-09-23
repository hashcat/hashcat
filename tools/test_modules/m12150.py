#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import re

from lib.test_helpers import random_bytes, split_hash_word

# Apache Shiro 1 SHA-512: SHA-512 of the salt and the password, then of the digest, iterations times
# in all.

LINE = re.compile(r"^\$shiro1\$SHA-512\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 1024 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1") if salt else random_bytes(16)

  digest = hashlib.sha512(salt_bytes + word).digest()

  for _ in range(1, iterations):
    digest = hashlib.sha512(digest).digest()

  return "$shiro1$SHA-512$%d$%s$%s" % (iterations, base64.b64encode(salt_bytes).decode(), base64.b64encode(digest).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  m = LINE.match(hash_in)

  if m is None:
    return None

  try:
    salt = base64.b64decode(m.group(2)).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, m.group(1)), word)
