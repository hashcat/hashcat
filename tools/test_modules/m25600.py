#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Protocol.KDF import bcrypt

# bcrypt(md5($pass)): bcrypt of the md5 hex digest of the password.

TO_STD = str.maketrans("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 5 if iterations is None or iterations == "" else int(iterations)

  pre = hashlib.md5(word).hexdigest().encode()

  return bcrypt(pre, cost, salt.encode("latin-1")).decode()


def module_verify_hash(line):
  idx = line.find(b":", 33)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  idx2 = hash_in.find("$", 4)

  salt = base64.b64decode(hash_in[idx2 + 1:idx2 + 23].translate(TO_STD) + "==")[:16].decode("latin-1")

  return (module_generate_hash(word, salt, hash_in[4:idx2]), word)
