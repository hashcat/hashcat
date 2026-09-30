#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import MD4

from lib.test_helpers import kernel_charset, utf16le

# MS SNTP: MD5 of the NT hash and the 48 byte packet. The two kernel families convert the password to
# UTF-16 differently, see kernel_charset (); MD4 is pycryptodome's, because hashlib often has none.

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [96, 96], [0, 27], [96, 96], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  digest = hashlib.md5(MD4.new(utf16le(word, CHARSET)).digest() + salt_bin).hexdigest()

  return "$sntp-ms$%s$%s" % (digest, salt_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("$")

  if len(data) < 4 or data[1] != "sntp-ms" or len(data[3]) != 96:
    return None

  try:
    return (module_generate_hash(word, data[3]), word)
  except ValueError:
    return None
