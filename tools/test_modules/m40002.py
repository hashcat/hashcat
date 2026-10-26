#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# Huawei / H3C / HPE Comware $h$6$: sha512 of the password, the salt and the password again, where
# each copy of the password carries its terminating zero byte. The digest is in base64.


def module_constraints():
  return [[0, 256], [1, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.sha512(word + b"\x00" + salt.encode() + word + b"\x00").digest()

  return "$h$6$%s$%s" % (salt, base64.b64encode(digest).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 5 or data[1] != "h" or data[2] != "6":
    return None

  return (module_generate_hash(word, data[3]), word)
