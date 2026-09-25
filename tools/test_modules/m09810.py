#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import oldoffice

# MS Office <= 2003 SHA1 + RC4, collider #1 (version 3): the candidate is the 5 byte RC4 key. Any
# second block already on the line is carried through unchanged.


def module_constraints():
  return [[-1, -1], [-1, -1], [5, 5], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None, param2=None):
  if not salt:
    return None

  rc4_key = word + b"\x00" * 11

  enc1, enc2 = oldoffice.encrypt_blocks(rc4_key, param, hashlib.sha1)

  secblock = "*%s" % param2 if param2 else ""

  return "$oldoffice$3*%s*%s*%s%s" % (salt, enc1, enc2, secblock)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if len(word) != 5:
    return None

  data = hash_in.split("*")

  if len(data) not in (4, 5) or data[0] != "$oldoffice$3":
    return None

  if len(data[1]) != 32 or len(data[2]) != 32 or len(data[3]) != 40:
    return None

  param2 = data[4] if len(data) == 5 else None

  return (module_generate_hash(word, data[1], None, data[2], param2), word)
