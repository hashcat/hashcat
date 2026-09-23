#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_word

# Kerberos 5 etype 17 (AES128-CTS key from the DB): PBKDF2-HMAC-SHA1 of the password
# over uppercase(realm)+user, then AES-CBC of the n-fold constant to derive the key.

NFOLD = bytes.fromhex("6b65726265726f737b9b5b2b93132b93")


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, user="user", realm="realm"):
  mysalt = (realm.upper() + user).encode()

  seed = hashlib.pbkdf2_hmac("sha1", word, mysalt, 4096, 16)

  iv = b"\x00" * 16

  key = AES.new(seed, AES.MODE_CBC, iv).encrypt(NFOLD)

  return "$krb5db$17$%s$%s$%s" % (user, realm, key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 5 or fields[1] != "krb5db" or fields[2] != "17":
    return None

  return (module_generate_hash(word, None, None, fields[3], fields[4]), word)
