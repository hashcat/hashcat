#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from lib.test_helpers import random_hex_string, split_hash_word

# XCA database password, sha512passwT () in lib/pki_evp.cpp: the salt is "T" and 16 hex
# characters, SHA-512 runs 8000 times over the salt and the password, and the stored value is the
# salt followed by the digest in uppercase hex.

LINE = re.compile(r"^T([0-9a-fA-F]{16})([0-9a-fA-F]{128})$")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if salt is None or len(salt) != 16:
    salt = random_hex_string(16)

  salt_text = "T" + salt

  digest = hashlib.sha512(salt_text.encode() + word).digest()

  for _ in range(1, 8000):
    digest = hashlib.sha512(digest).digest()

  return salt_text + digest.hex().upper()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  m = LINE.match(hash_in)

  if m is None:
    return None

  return (module_generate_hash(word, m.group(1)), word)
