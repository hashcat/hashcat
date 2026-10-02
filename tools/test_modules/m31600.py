#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import MD4

from lib.test_helpers import pack_hex, split_hash_word

# Domain Cached Credentials 2 (DCC2), MS Cache 2 (NT): as 2100, from the NT hash in hex rather than
# the password. MD4 is pycryptodome's, because hashlib often has none.


def module_constraints():
  return [[32, 32], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_get_random_password(word):
  # the password widened to UTF-16LE byte by byte, as the perl did

  return MD4.new(word.decode("latin-1").encode("utf-16-le")).hexdigest().encode()


def module_generate_hash(word, salt, iterations=None):
  iterations = 10240 if iterations is None else int(iterations)

  salt_bin = salt.lower().encode("utf-16-le")

  dcc1 = MD4.new(pack_hex(word) + salt_bin).digest()

  digest = hashlib.pbkdf2_hmac("sha1", dcc1, salt_bin, iterations, 16).hex()

  return "$DCC2$%d#%s#%s" % (iterations, salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$DCC2$"):
    return None

  data = hash_in[6:].split("#")

  if len(data) != 3:
    return None

  return (module_generate_hash(word, data[1], data[0]), word)
