#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import re

from lib.test_helpers import split_hash_word

# Bitwarden: PBKDF2-HMAC-SHA256 of the password salted with the e-mail, then a second PBKDF2 with the
# roles swapped, the password as salt.


def module_constraints():
  return [[0, 256], [1, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iterations2=None):
  iterations = 10000 if iterations is None else int(iterations)
  iterations2 = 2 if iterations2 is None else int(iterations2)

  email = salt.encode("latin-1") if isinstance(salt, str) else salt

  digest1 = hashlib.pbkdf2_hmac("sha256", word, email, iterations, 32)
  digest2 = hashlib.pbkdf2_hmac("sha256", digest1, word, iterations2, 32)

  return "$bitwarden$2*%d*%d*%s*%s" % (iterations, iterations2, base64.b64encode(email).decode(), base64.b64encode(digest2).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) < 5 or data[0] != "$bitwarden$2":
    return None

  if not re.fullmatch(r"[0-9]{1,7}", data[1]) or not re.fullmatch(r"[0-9]{1,7}", data[2]):
    return None

  if not re.fullmatch(r"[a-zA-Z0-9+/=]+", data[3]) or not re.fullmatch(r"[a-zA-Z0-9+/=]+", data[4]):
    return None

  try:
    email = base64.b64decode(data[3])
  except binascii.Error:
    return None

  return (module_generate_hash(word, email, data[1], data[2]), word)
