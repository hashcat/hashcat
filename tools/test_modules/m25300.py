#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# MS Office 2016 SheetProtection: SHA-512 of the salt and the UTF-16LE password, then of the digest
# and the round number as 4 little endian bytes, iterations times. The two kernel families convert
# the password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 100000 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  tmp = hashlib.sha512(salt_bytes + utf16le(word, CHARSET)).digest()

  for i in range(iterations):
    tmp = hashlib.sha512(tmp + i.to_bytes(4, "little")).digest()

  return "$office$2016$0$%d$%s$%s" % (iterations, base64.b64encode(salt_bytes).decode(), base64.b64encode(tmp).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 7 or data[1:4] != ["office", "2016", "0"] or len(data[5]) != 24 or len(data[6]) != 88:
    return None

  return (module_generate_hash(word, base64.b64decode(data[5]).decode("latin-1"), data[4]), word)
