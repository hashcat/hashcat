#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import MD4

from lib.test_helpers import kernel_charset, split_hash_word, utf16le

# JavaScript MD4 (double UTF-16LE): md4(utf16le(md4(utf16le(pass)))). The two kernel families convert
# the password to UTF-16 differently, see kernel_charset (); MD4 is pycryptodome's.

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  inner = MD4.new(utf16le(word, CHARSET)).digest()

  return MD4.new(inner.decode("latin-1").encode("utf-16-le")).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
