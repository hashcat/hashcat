#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_word

# Blockchain, My Wallet: PBKDF2-HMAC-SHA1 (10 rounds) of the password over the 16 byte salt, then
# AES-256-CBC of a fixed JSON header, the salt as IV.

DATA = (b'{\n"guid" : "00000000-0000-0000-0000-000000000000",\n'
        b'"sharedKey" : "00000000-0000-0000-0000-000000000000",\n'
        b'"options" : {"pbkdf2_iterations":10,"fee_policy":0,"html5_notifications":false,'
        b'"logout_time":600000,"tx_display":0,"always_keep_local_backup":false}')


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, encrypted=None):
  salt_bin = bytes.fromhex(salt)

  if encrypted is None:
    key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, 10, 32)

    from Crypto.Util.Padding import pad

    encrypted = AES.new(key, AES.MODE_CBC, salt_bin).encrypt(pad(DATA, 16)).hex()

  return "$blockchain$%d$%s%s" % (len(salt + encrypted) // 2, salt, encrypted)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 4 or fields[1] != "blockchain":
    return None

  data = fields[3]

  if int(fields[2]) * 2 != len(data):
    return None

  return (module_generate_hash(word, data[:32], None, data[32:]), word)
