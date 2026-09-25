#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import struct

from Crypto.Cipher import AES

from lib import office
from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# MS Office 2007: 50000 rounds of SHA1, an 0x36/0x5c derivation to the AES key, then AES-ECB.

CHARSET = kernel_charset()


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None, aes_key_size=128):
  aes_key_size = int(aes_key_size)

  salt_bin = bytes.fromhex(salt)

  tmp = office.iterated_key(hashlib.sha1, salt_bin, utf16le(word, CHARSET), 50000)

  tmp = hashlib.sha1(tmp + struct.pack("<I", 0)).digest()

  b1 = bytes((0x36 ^ tmp[i]) if i < len(tmp) else 0x36 for i in range(64))
  b2 = bytes((0x5c ^ tmp[i]) if i < len(tmp) else 0x5c for i in range(64))

  key = (hashlib.sha1(b1).digest() + hashlib.sha1(b2).digest())[:aes_key_size // 8]

  cipher = AES.new(key, AES.MODE_ECB)

  encdata = cipher.decrypt(bytes.fromhex(param)) if param else b"A" * 16

  data1 = (encdata + b"\x00" * 16)[:16]
  data2 = (hashlib.sha1(encdata[:16]).digest() + b"\x00" * 16)[:32]

  enc1 = cipher.encrypt(data1).hex()[:32]
  enc2 = cipher.encrypt(data2).hex()[:40]

  return "$office$*2007*20*%d*16*%s*%s*%s" % (aes_key_size, salt, enc1, enc2)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) < 8 or data[1] != "$office$"[:0] + "2007" or data[3] not in ("128", "256"):
    return None

  return (module_generate_hash(word, data[5], None, data[6], data[3]), word)
