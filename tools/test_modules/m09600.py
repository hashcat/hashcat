#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib import office
from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# MS Office 2013: 100000 rounds of SHA512, two block keys, AES-256-CBC with the salt as IV.

CHARSET = kernel_charset()

IN_KEY = b"\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79"
VAL_KEY = b"\xd7\xaa\x0f\x6d\x30\x61\x34\x4e"


def module_constraints():
  return [[0, 15], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None):
  iterations = 100000 if iterations is None else int(iterations)

  salt_bin = bytes.fromhex(salt)

  tmp = office.iterated_key(hashlib.sha512, salt_bin, utf16le(word, CHARSET), iterations)

  key1 = hashlib.sha512(tmp + IN_KEY).digest()[:32]
  key2 = hashlib.sha512(tmp + VAL_KEY).digest()[:32]

  encdata = AES.new(key1, AES.MODE_CBC, salt_bin).decrypt(bytes.fromhex(param)) if param else b"A" * 16

  data1 = encdata
  data2 = hashlib.sha512(data1[:16]).digest()

  enc1 = AES.new(key1, AES.MODE_CBC, salt_bin).encrypt(data1).hex()
  enc2 = AES.new(key2, AES.MODE_CBC, salt_bin).encrypt(data2[:32]).hex()[:64]

  return "$office$*2013*%d*256*16*%s*%s*%s" % (iterations, salt, enc1, enc2)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) < 8 or data[1] != "2013" or data[3] != "256":
    return None

  return (module_generate_hash(word, data[5], data[2], data[6]), word)
