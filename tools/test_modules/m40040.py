#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import struct
import zlib

from base64 import b64decode, b64encode

# Blockchain, My Wallet, Second Password (SHA256). The 16 byte salt is printed as a UUID, hashed
# with the word and iterated, then packed with the salt, the iteration count and a crc32 tail and
# base64 encoded.


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  iterations = 10000 if iterations is None else int(iterations)

  uuid = "%s-%s-%s-%s-%s" % (salt[0:4].hex(), salt[4:6].hex(), salt[6:8].hex(),
                             salt[8:10].hex(), salt[10:16].hex())

  digest = hashlib.sha256(uuid.encode("ascii") + word).digest()

  for _ in range(iterations - 1):
    digest = hashlib.sha256(digest).digest()

  data = b"bs:" + digest + salt + struct.pack("<L", iterations)

  data += struct.pack("<L", zlib.crc32(data) & 0xffffffff)

  return b64encode(data).decode("ascii")


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if len(hash_in) != 80:
    return None

  bin_string = b64decode(hash_in)

  if bin_string[0:3] != b"bs:":
    return None

  if struct.pack("<L", zlib.crc32(bin_string[0:55]) & 0xffffffff) != bin_string[55:59]:
    return None

  salt = bin_string[35:51]
  iterations = struct.unpack("<L", bin_string[51:55])[0]

  return (module_generate_hash(word, salt, iterations), word)
