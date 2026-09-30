#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Protocol.KDF import bcrypt

# bcrypt(sha512) $2a$: the word is hashed with SHA-512, and its hex digest is the bcrypt password.
# Eksblowfish uses only the first 72 key bytes, so the 128 char digest is truncated to match.

BCRYPT64 = str.maketrans("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 12 if iterations is None or iterations == "" else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  sha512_word = hashlib.sha512(word).hexdigest().encode()[:72]

  return bcrypt(sha512_word, cost, salt_bytes).decode()


def module_verify_hash(line):
  idx = line.find(b":", 33)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  idx2 = hash_in.find("$", 4)

  salt64 = hash_in[idx2 + 1:idx2 + 23].translate(BCRYPT64)

  salt = base64.b64decode(salt64 + "==")[:16]

  return (module_generate_hash(word, salt, hash_in[4:idx2]), word)
