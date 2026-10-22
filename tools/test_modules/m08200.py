#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import random_bytes

# 1Password, cloudkeychain: PBKDF2-HMAC-SHA512 of the password, and HMAC-SHA256 over the data with
# the second half of the key. The salt argument carries the 16 byte salt and the 304 data bytes, in
# hex, one after the other.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 40000 if iterations is None else int(iterations)

  if not salt:
    salt = random_bytes(16 + 304).hex()

  salt_hex, data_hex = salt[:32], salt[32:]

  key = hashlib.pbkdf2_hmac("sha512", word, bytes.fromhex(salt_hex), iterations)

  digest = hmac.new(key[32:64], bytes.fromhex(data_hex), hashlib.sha256).hexdigest()

  return "%s:%s:%d:%s" % (digest, salt_hex, iterations, data_hex)


def module_verify_hash(line):
  data = line.split(b":", 4)

  if len(data) < 5:
    return None

  _, salt, iterations, blob, word = data

  try:
    return (module_generate_hash(word, (salt + blob).decode(), iterations.decode()), word)
  except ValueError:
    return None
