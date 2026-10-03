#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# Juniper NetScreen/SSG: md5 of "salt:Administration Tools:pass", which takes 23 bytes of the
# password and salt buffers, then a base64 of its own with six fixed characters mixed in.

ITOA64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

OBFUSCATE = ((0, "n"), (6, "r"), (12, "c"), (17, "s"), (23, "t"), (29, "n"))


def module_constraints():
  return [[0, 232], [0, 232], [0, 32], [0, 28], [0, 32]]


def module_generate_hash(word, salt, iterations=None):
  md5 = hashlib.md5(salt.encode() + b":Administration Tools:" + word).digest()

  res = ""

  for pos in range(0, 16, 2):
    num = (md5[pos] << 8) | md5[pos + 1]

    res += ITOA64[(num >> 12) & 0x0f] + ITOA64[(num >> 6) & 0x3f] + ITOA64[num & 0x3f]

  for idx, char in OBFUSCATE:
    res = res[:idx] + char + res[idx:]

  return "%s:%s" % (res, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
