#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Cisco-PIX MD5: MD5 of the zero padded password, 12 bytes of it in a base64 of its own.

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def pseudo_base64(md5):
  out = ""

  for i in range(4):
    v = int.from_bytes(md5[i * 4:i * 4 + 4], "little")

    for _ in range(4):
      out += ITOA64[v & 0x3f]
      v >>= 6

  return out


def padded_md5(data):
  # zero padded to a multiple of 16, the empty string included

  return hashlib.md5(data + b"\x00" * (-len(data) % 16)).digest()


def module_constraints():
  return [[-1, -1], [-1, -1], [1, 31], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return pseudo_base64(padded_md5(word))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
