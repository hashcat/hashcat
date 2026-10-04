#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import hmac
import re

from lib.test_helpers import random_number, random_string, split_hash_word

# MongoDB ServerKey SCRAM-SHA-256: HMAC-SHA256 of "Server Key" keyed with PBKDF2-HMAC-SHA256
# of the password, the user name drawn at random.


def module_constraints():
  return [[0, 256], [28, 28], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, user=None):
  iterations = 15000 if iterations is None else int(iterations)

  if user is None:
    user = random_string(random_number(0, 64)).encode()

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, 32)

  digest = hmac.new(key, b"Server Key", hashlib.sha256).digest()

  return "$mongodb-scram$*1*%s*%d*%s*%s" % (base64.b64encode(user).decode(), iterations,
                                             base64.b64encode(salt_bytes).decode(), base64.b64encode(digest).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$mongodb-scram$*1"):
    return None

  data = hash_in.split("*")

  if len(data) < 5:
    return None

  _, _, user, iterations, salt = data[:5]

  if not re.fullmatch(r"[A-Za-z0-9+/=]{0,88}", user) or not re.fullmatch(r"[1-9][0-9]{0,7}", iterations):
    return None

  if not re.fullmatch(r"[A-Za-z0-9+/=]{40}", salt):
    return None

  try:
    user = base64.b64decode(user)
    salt = base64.b64decode(salt)
  except binascii.Error:
    return None

  if len(user) > 64:
    return None

  return (module_generate_hash(word, salt, iterations, user), word)
