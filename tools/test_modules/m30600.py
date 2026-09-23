#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Protocol.KDF import bcrypt

# bcrypt(sha256($pass)) with a $2b prefix. The word is hashed with SHA-256 and its 64 char hex
# digest is the bcrypt password. pycryptodome emits a $2a crypt string; for passwords this short
# $2a and $2b produce identical hash bytes, so only the version tag is rewritten.

BCRYPT64 = str.maketrans("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 10 if iterations is None or iterations == "" else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  sha256_word = hashlib.sha256(word).hexdigest().encode()

  full = bcrypt(sha256_word, cost, salt_bytes)

  return "$2b$" + full[4:].decode()


def module_verify_hash(line):
  idx = line.find(b":", 33)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  idx2 = hash_in.find("$", 4)

  iter = hash_in[4:idx2]

  salt64 = hash_in[idx2 + 1:idx2 + 23].translate(BCRYPT64)

  salt = base64.b64decode(salt64 + "==")[:16]

  return (module_generate_hash(word, salt, iter), word)
