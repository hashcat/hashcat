#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac

from Crypto.Protocol.KDF import bcrypt

# WordPress bcrypt (>= 6.8). The password is HMAC-SHA384'd under a fixed key, base64 encoded and fed
# to bcrypt, which keeps the input under the 72 byte cap. The stored hash is bcrypt's own $2a$/$2y$
# string with a leading $wp.

# bcrypt's base64 alphabet mapped onto the standard one, so a stored salt field decodes with the
# stdlib. Same table m03200 uses.

BCRYPT64 = str.maketrans("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 5 if iterations is None or iterations == "" else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  digest = hmac.new(b"wp-sha384", word, hashlib.sha384).digest()

  encoded_hmac = base64.b64encode(digest)

  return "$wp" + bcrypt(encoded_hmac, cost, salt_bytes).decode()


def module_verify_hash(line):
  idx = line.find(b":", 33)

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  # $wp$<version>$<cost>$<salt><digest>. The perl oracle parses the version as the cost here and
  # cannot round trip its own output, so this reads the real cost and salt instead.

  if not hash_in.startswith("$wp$"):
    return None

  fields = hash_in[4:].split("$")

  if len(fields) != 3 or len(fields[2]) < 22:
    return None

  cost = fields[1]

  salt64 = fields[2][:22].translate(BCRYPT64)

  try:
    salt = base64.b64decode(salt64 + "==")[:16]
  except (ValueError, base64.binascii.Error):
    return None

  if len(salt) != 16:
    return None

  return (module_generate_hash(word, salt, cost), word)
