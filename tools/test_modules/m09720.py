#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import oldoffice

# MS Office <= 2003 MD5 + RC4, collider #2: as 9700, and the 5 byte intermediate key is appended to
# the line so the collider can recover it.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None, version=None):
  salt_bin = bytes.fromhex(salt)

  tmp = hashlib.md5(word.decode("latin-1").encode("utf-16-le")).digest()[:5]
  tmp = hashlib.md5((tmp + salt_bin) * 16).digest()[:5]

  rc4key = tmp

  if version is None:
    version = 0 if (int.from_bytes(tmp[:4], "little") & 1) else 1

  rc4_key = hashlib.md5(tmp + b"\x00\x00\x00\x00").digest()[:16]

  enc1, enc2 = oldoffice.encrypt_blocks(rc4_key, param, hashlib.md5)

  return "$oldoffice$%d*%s*%s*%s:%s" % (version, salt, enc1, enc2, rc4key.hex())


def module_verify_hash(line):
  fields = line.split(b":", 2)

  if len(fields) != 3 or len(fields[1]) != 10:
    return None

  hash_in, word = fields[0].decode(errors="replace"), fields[2]

  data = hash_in.split("*")

  if len(data) != 4 or data[0] not in ("$oldoffice$0", "$oldoffice$1"):
    return None

  if len(data[1]) != 32 or len(data[2]) != 32 or len(data[3]) != 32:
    return None

  try:
    return (module_generate_hash(word, data[1], None, data[2], int(data[0][11])), word)
  except ValueError:
    return None
