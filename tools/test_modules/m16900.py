#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import random_hex_string, split_hash_word

# Ansible Vault: PBKDF2-HMAC-SHA256 of the password (80 bytes, of which the last 16 are the IV and not
# needed here), then HMAC-SHA256 over the ciphertext keyed with bytes 32 to 64.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, ciphertext=None):
  if ciphertext is None:
    ciphertext = random_hex_string(64)

  if not salt:
    salt = random_hex_string(64)

  key = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), 10000, 64)

  digest = hmac.new(key[32:64], bytes.fromhex(ciphertext), hashlib.sha256).hexdigest()

  return "$ansible$0*0*%s*%s*%s" % (salt, ciphertext, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 5 or data[0].split("$")[1:2] != ["ansible"]:
    return None

  try:
    return (module_generate_hash(word, data[2], None, data[3]), word)
  except ValueError:
    return None
