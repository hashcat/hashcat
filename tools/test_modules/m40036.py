#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Oracle T: PBKDF2-HMAC-SHA512 salted with the 16 byte salt and AUTH_PBKDF2_SPEEDY_KEY, then SHA-512
# of the key and the salt, all in upper case hex.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha512", word, salt_bin + b"AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)

  return (hashlib.sha512(key + salt_bin).hexdigest() + salt).upper()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if len(hash_in) != 160:
    return None

  try:
    return (module_generate_hash(word, hash_in[128:160]), word)
  except ValueError:
    return None
