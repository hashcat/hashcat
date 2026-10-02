#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import oldoffice

# MS Office <= 2003 SHA1 + RC4. Version 3 uses a 40 bit key (5 bytes then nul), version 4 a full 128
# bit key, and version 3 carries an optional second block. See lib/oldoffice.py.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None, version=None, param3=None):
  salt_bin = bytes.fromhex(salt)

  tmp = hashlib.sha1(salt_bin + word.decode("latin-1").encode("utf-16-le")).digest()

  if version is None:
    version = 3 if (int.from_bytes(tmp[:4], "little") & 1) else 4

  key = hashlib.sha1(tmp + b"\x00\x00\x00\x00").digest()

  rc4_key = (key[:5] + b"\x00" * 11 if version == 3 else key)[:16]

  enc1, enc2 = oldoffice.encrypt_blocks(rc4_key, param, hashlib.sha1)

  secblock = ""

  if version == 3:
    key2 = hashlib.sha1(tmp + b"\x01\x00\x00\x00").digest()[:5] + b"\x00" * 11

    if param3 is not None:
      secblock = oldoffice.secblock_v3(key2, param3)
    else:
      from lib.test_helpers import random_number

      if random_number(0, 1) == 1:
        secblock = oldoffice.random_secblock_v3(key2)

  return "$oldoffice$%d*%s*%s*%s%s" % (version, salt, enc1, enc2, secblock)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("*")

  if len(data) not in (4, 5) or data[0] not in ("$oldoffice$3", "$oldoffice$4"):
    return None

  if len(data[1]) != 32 or len(data[2]) != 32 or len(data[3]) != 40:
    return None

  param3 = data[4] if len(data) == 5 else ""

  try:
    return (module_generate_hash(word, data[1], None, data[2], int(data[0][11]), param3), word)
  except ValueError:
    return None
