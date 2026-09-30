#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import MD4

from lib.test_helpers import pack_hex, split_hash_salt_word

# Domain Cached Credentials (DCC), MS Cache (NT): the password is the NT hash, in hex; MD4 of it and
# the lower cased user name in UTF-16LE. MD4 is pycryptodome's, because hashlib often has none.


def module_constraints():
  return [[32, 32], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_get_random_password(word):
  # the password widened to UTF-16LE byte by byte, as the perl did

  return MD4.new(word.decode("latin-1").encode("utf-16-le")).hexdigest().encode()


def module_generate_hash(word, salt, iterations=None):
  digest = MD4.new(pack_hex(word) + salt.lower().encode("utf-16-le")).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
