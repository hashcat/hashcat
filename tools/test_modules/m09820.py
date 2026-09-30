#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import oldoffice

# MS Office <= 2003 SHA1 + RC4, collider #2 (version 3): as 9820's parent, and the 5 byte
# intermediate key is appended to the line so the collider can recover it.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None, param2=None):
  salt_bin = bytes.fromhex(salt)

  tmp = hashlib.sha1(salt_bin + word.decode("latin-1").encode("utf-16-le")).digest()

  rc4key = hashlib.sha1(tmp + b"\x00\x00\x00\x00").digest()[:5]

  rc4_key = rc4key + b"\x00" * 11

  enc1, enc2 = oldoffice.encrypt_blocks(rc4_key, param, hashlib.sha1)

  key2 = hashlib.sha1(tmp + b"\x01\x00\x00\x00").digest()[:5] + b"\x00" * 11

  secblock = oldoffice.secblock_v3(key2, param2) if param2 else ""

  return "$oldoffice$3*%s*%s*%s%s:%s" % (salt, enc1, enc2, secblock, rc4key.hex())


def module_verify_hash(line):
  fields = line.split(b":", 2)

  if len(fields) != 3 or len(fields[1]) != 10:
    return None

  hash_in, word = fields[0].decode(errors="replace"), fields[2]

  data = hash_in.split("*")

  if len(data) not in (4, 5) or data[0] != "$oldoffice$3":
    return None

  if len(data[1]) != 32 or len(data[2]) != 32 or len(data[3]) != 40:
    return None

  param2 = data[4] if len(data) == 5 else None

  try:
    return (module_generate_hash(word, data[1], None, data[2], param2), word)
  except ValueError:
    return None
