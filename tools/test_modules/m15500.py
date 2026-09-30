#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import pack_hex, random_hex_string, random_number, split_hash_word

# JKS Java Key Store private keys (SUN): the password widened to UTF-16BE byte by byte, a SHA-1
# keystream XORed over the encrypted key, and SHA-1 over the password and the plain key as the
# check.


def module_constraints():
  return [[0, 16], [-1, -1], [0, 16], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, enc_key=None, alias=None):
  iv = pack_hex(salt or random_hex_string(40))
  enc = pack_hex(enc_key or random_hex_string(random_number(1, 1500)))
  alias = alias or "test"

  wide = word.decode("latin-1").encode("utf-16-be")

  digest = hashlib.sha1(wide + iv).digest()

  der1, der2 = digest[0:1], digest[6:20]

  key = bytearray()

  for i in range(0, len(enc), 20):
    key += bytes(a ^ b for a, b in zip(enc[i:i + 20], digest))

    digest = hashlib.sha1(wide + digest).digest()

  check = hashlib.sha1(wide + bytes(key)).digest()

  return "$jksprivk$*%s*%s*%s*%s*%s*%s" % (check.hex().upper(), iv.hex().upper(), enc.hex().upper(),
                                            der1.hex().upper(), der2.hex().upper(), alias)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 7 or data[0] != "$jksprivk$":
    return None

  try:
    return (module_generate_hash(word, data[2], None, data[3], data[6]), word)
  except ValueError:
    return None
