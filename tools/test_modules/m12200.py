#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# eCryptfs: SHA-512 of the 8 byte salt and the password, then 65536 more rounds, 8 bytes of it. A
# line without the salt field means the default salt.

DEFAULT_SALT = "0011223344556677"


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, default_salt=False):
  if default_salt:
    salt = DEFAULT_SALT

  digest = hashlib.sha512(bytes.fromhex(salt) + word).digest()

  for _ in range(65536):
    digest = hashlib.sha512(digest).digest()

  if default_salt:
    return "$ecryptfs$0$%s" % digest.hex()[:16]

  return "$ecryptfs$0$1$%s$%s" % (salt, digest.hex()[:16])


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$ecryptfs$0$"):
    return None

  data = hash_in[12:].split("$")

  try:
    if data[0] == "1" and len(data) >= 3:
      return (module_generate_hash(word, data[1]), word)

    return (module_generate_hash(word, None, None, True), word)
  except ValueError:
    return None
