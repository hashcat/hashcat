#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64

from Crypto.Protocol.KDF import bcrypt

# bcrypt(bcrypt) $2a$: the word is bcrypt hashed once, and that 60 char hash string is the password
# for a second bcrypt with the same cost and salt. pycryptodome's bcrypt writes the $2a$ string
# itself from a 16 byte salt and a cost of 5 unless the line says otherwise.

BCRYPT64 = str.maketrans("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def module_constraints():
  return [[0, 72], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 5 if iterations is None or iterations == "" else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  hash1 = bcrypt(word, cost, salt_bytes)

  return bcrypt(hash1, cost, salt_bytes).decode()


def module_verify_hash(line):
  idx = line.find(b":", 33)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  idx2 = hash_in.find("$", 4)

  salt64 = hash_in[idx2 + 1:idx2 + 23].translate(BCRYPT64)

  salt = base64.b64decode(salt64 + "==")[:16]

  return (module_generate_hash(word, salt, hash_in[4:idx2]), word)
