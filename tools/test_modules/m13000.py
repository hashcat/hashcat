#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# RAR5: PBKDF2-HMAC-SHA256 with 2^n + 32 rounds, the 32 byte key folded to 8 by XOR.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iv="0" * 32):
  iterations = 15 if iterations is None else int(iterations)

  key = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), (1 << iterations) + 32, 32)

  check = bytes(key[i] ^ key[i + 8] ^ key[i + 16] ^ key[i + 24] for i in range(8))

  return "$rar5$16$%s$%d$%s$8$%s" % (salt, iterations, iv, check.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 8 or data[1] != "rar5" or data[2] != "16" or data[6] != "8":
    return None

  try:
    return (module_generate_hash(word, data[3], data[4], data[5]), word)
  except ValueError:
    return None
