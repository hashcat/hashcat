#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import crypt_r

from lib.test_helpers import random_number

# BSDi Crypt / extended DES ("_" scheme). crypt_r builds the whole "_<iter><salt><hash>" string; the
# iteration count is 4 crypt64 characters, the salt 4.

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _int24(v):
  return "".join(ITOA64[(v >> (6 * i)) & 0x3f] for i in range(4))


def module_constraints():
  return [[1, 31], [4, 4], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = random_number(1, 5000) if iterations is None else int(iterations)

  return crypt_r.crypt(word.decode("utf-8"), "_" + _int24(iterations) + salt)


def module_verify_hash(line):
  if not line.startswith(b"_") or line.find(b":", 20) != 20:
    return None

  hash_in, word = line[:20].decode(errors="replace"), line[21:]

  iterations = sum(ITOA64.index(hash_in[1 + i]) << (6 * i) for i in range(4))
  salt = hash_in[5:9]

  return (module_generate_hash(word, salt, iterations), word)
