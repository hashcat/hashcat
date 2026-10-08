#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# EPiServer 6.x (v<4): SHA1 over the salt and the password in UTF-16LE, both base64 encoded, the
# digest cut to 27 characters. The two kernel families convert the password to UTF-16 differently,
# see kernel_charset ().

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [0, 256], [0, 27], [0, 27], [0, 27]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  digest = hashlib.sha1(salt_bytes + utf16le(word, CHARSET)).digest()

  return "$episerver$*0*%s*%s" % (base64.b64encode(salt_bytes).decode(), base64.b64encode(digest).decode()[:27])


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in[14:].split("*")

  if len(fields) < 2:
    return None

  try:
    salt = base64.b64decode(fields[0]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt), word)
