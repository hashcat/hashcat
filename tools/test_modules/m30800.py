#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string, split_hash_word

# TronLink wallet keystore. PBKDF2-HMAC-SHA512 of the password over the salt runs a single
# iteration for a 32 byte AES-256-CTR key, and the counter block starts at 1 because that is the
# aes-js default the wallet relies on. The plaintext is the private key as 64 hex characters and
# the keystore stores no MAC, so a candidate is judged on the plaintext reading as hex. The
# tronscan wizard that writes these files produces upper case, so generation does too, and both
# cases are accepted.
#
# The salt is free text in the keystore rather than a hex field, so the salt this module is handed
# is used as it stands and the hash line carries its hex encoding.

CT_LEN = 64


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def _ctr(key):
  return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=1)


def _is_hex(pt):
  return all(chr(b) in "0123456789abcdefABCDEF" for b in pt)


def module_generate_hash(word, salt, ciphertext=None):
  salt_bin = salt.encode("utf-8") if isinstance(salt, str) else salt

  key = hashlib.pbkdf2_hmac("sha512", word, salt_bin, 1, 32)

  if ciphertext is None:
    pt = random_hex_string(CT_LEN).upper().encode("ascii")
  else:
    pt = _ctr(key).decrypt(bytes.fromhex(ciphertext))

    if _is_hex(pt) is False:
      pt = b""

  ct = _ctr(key).encrypt(pt)

  return "$tronlink$%s*%s" % (salt_bin.hex(), ct.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if hash_in[:10] != "$tronlink$":
    return None

  fields = hash_in[10:].split("*")

  if len(fields) != 2:
    return None

  salt_hex, ciphertext = fields

  if len(ciphertext) != CT_LEN * 2:
    return None

  try:
    salt_bin = bytes.fromhex(salt_hex)

    bytes.fromhex(ciphertext)
  except ValueError:
    return None

  return (module_generate_hash(word, salt_bin, ciphertext), word)
