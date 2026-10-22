#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.test_helpers import split_hash_salt_word

# Oracle H: type DES (Oracle): the upper cased user name and password, each byte widened to two big
# endian bytes, zero padded to a block, DES-CBC encrypted under a fixed key; the last block keys a
# second pass, whose last block is the hash.

KEY = bytes.fromhex("0123456789ABCDEF")


def last_block(key, data):
  return DES.new(key, DES.MODE_CBC, b"\x00" * 8).encrypt(data)[-8:]


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 30], [1, 30], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  # perl's uc () folds ASCII only in a byte string, and so does bytes.upper ()

  userpass = b"".join(b"\x00" + bytes([c]) for c in (salt.encode() + word).upper())

  userpass += b"\x00" * (-len(userpass) % 8)

  digest = last_block(last_block(KEY, userpass), userpass)

  return "%s:%s" % (digest.hex().upper(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
