#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Stargazer Stellar Wallet XLM: eight base62 digits, each folding one byte pair of the MD5 of the
# password down into 0..61.

ITOA62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  digest = hashlib.md5(word).digest()

  chksum = []

  for i in range(0, 16, 2):
    idx = ((digest[i] + digest[i + 1]) & 0xff) % 62

    chksum.append(ITOA62[idx])

  return "".join(chksum)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  return (module_generate_hash(word), word)
