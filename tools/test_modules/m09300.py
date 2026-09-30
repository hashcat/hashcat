#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# Cisco-IOS $9$ (scrypt): N=16384, r=1, p=1, the 32 byte key in Cisco's base64 alphabet.

CISCO = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def module_constraints():
  return [[0, 256], [14, 14], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  key = hashlib.scrypt(word, salt=salt.encode(), n=16384, r=1, p=1, dklen=32, maxmem=(128 * 16384 * 2))

  return "$9$%s$%s" % (salt, base64.b64encode(key).decode()[:43].translate(CISCO))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$9$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 4 or len(fields[2]) != 14:
    return None

  return (module_generate_hash(word, fields[2]), word)
