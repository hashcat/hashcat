#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_word

# Blockchain, My Wallet, second password. A one iteration PBKDF2-HMAC-SHA1 of the password over the
# 16 byte salt gives a 32 byte AES key, and a fixed wallet JSON prefix is AES-256-OFB encrypted with
# the salt as IV. The hash carries the salt and the ciphertext concatenated as hex.

DATA = (b'{\n'
        b'"guid" : "00000000-0000-0000-0000-000000000000",\n'
        b'"sharedKey" : "00000000-0000-0000-0000-000000000000",\n'
        b'"options" : {"pbkdf2_iterations":10,"fee_policy":0,"html5_notifications":false,'
        b'"logout_time":600000,"tx_display":0,"always_keep_local_backup":false}')


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, encrypted=None):
  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, 1, 32)

  if encrypted is None:
    cipher = AES.new(key, AES.MODE_OFB, iv=salt_bin)
    encrypted = cipher.encrypt(DATA).hex()

  body = salt + encrypted

  return "$blockchain$%d$%s" % (len(body) // 2, body)


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  data = hash_str.split("$")

  if len(data) != 4:
    return None

  signature = data[1]
  data_len = data[2]
  body = data[3]

  if signature != "blockchain":
    return None

  try:
    if int(data_len) * 2 != len(body):
      return None
  except ValueError:
    return None

  salt = body[:32]
  encrypted = body[32:]

  return (module_generate_hash(word, salt, encrypted), word)
