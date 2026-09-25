#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import MD4
from lib.test_helpers import kernel_charset, split_hash_salt_word, utf16le

# hashlib has no MD4 wherever OpenSSL ships without the legacy provider, so this is
# pycryptodome's.

# The two kernel families convert the password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [0, 256], [0, 27], [0, 19], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  digest = MD4.new(MD4.new(utf16le(word, CHARSET)).digest() + salt.lower().encode("utf-16-le")).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
