#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import oldoffice

# MS Office <= 2003 MD5 + RC4, collider #1: the candidate is the 5 byte RC4 key itself.


def module_constraints():
  return [[-1, -1], [-1, -1], [5, 5], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None, version=None):
  if not salt:
    return None

  if version is None:
    version = 0 if (int.from_bytes(word[:4], "little") & 1) else 1

  rc4_key = hashlib.md5(word + b"\x00\x00\x00\x00").digest()[:16]

  enc1, enc2 = oldoffice.encrypt_blocks(rc4_key, param, hashlib.md5)

  return "$oldoffice$%d*%s*%s*%s" % (version, salt, enc1, enc2)


def module_verify_hash(line):
  # the candidate is a binary RC4 key, so a colon is an ordinary byte: cut once, at the first colon

  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("*")

  if len(data) != 4 or data[0] not in ("$oldoffice$0", "$oldoffice$1"):
    return None

  if len(data[1]) != 32 or len(data[2]) != 32 or len(data[3]) != 32 or len(word) != 5:
    return None

  return (module_generate_hash(word, data[1], None, data[2], int(data[0][11])), word)
