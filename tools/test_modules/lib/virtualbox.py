#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# VirtualBox full disk encryption for the 27500 and 27600 test modules: PBKDF2-HMAC-SHA256 of the
# password gives the AES-XTS key, the key decrypts the stored encrypted password, and a second
# PBKDF2-HMAC-SHA256 over what came out is the hash.
#
# 27500 is AES-128-XTS, a 32 byte key of two halves; 27600 is AES-256-XTS, a 64 byte key.

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lib.test_helpers import random_hex_string


def generate_hash(key_len, iter1_default, word, salt1, iter1=None, enc_pass=None, salt2=None, iter2=None):
  iter1    = iter1_default if iter1 is None else iter1
  enc_pass = random_hex_string(2 * key_len) if enc_pass is None else enc_pass
  salt2    = random_hex_string(64) if salt2 is None else salt2
  iter2    = 20000 if iter2 is None else iter2

  key = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt1), iter1, key_len)

  decryptor = Cipher(algorithms.AES(key), modes.XTS(b"\x00" * 16)).decryptor()

  dec_pass = decryptor.update(bytes.fromhex(enc_pass)[:key_len])

  digest = hashlib.pbkdf2_hmac("sha256", dec_pass, bytes.fromhex(salt2), iter2, 32)

  return "$vbox$0$%d$%s$%d$%s$%d$%s$%s" % (iter1, salt1, key_len // 4, enc_pass, iter2, salt2, digest.hex())


def verify_hash(key_len, iter1_default, line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  parts = hash_in.split("$")

  if len(parts) < 9 or parts[1] != "vbox" or parts[2] != "0":
    return None

  _, _, _, iter1, salt1, klen, enc_pass, iter2, salt2 = parts[:9]

  if klen != str(key_len // 4) or len(salt1) != 64 or len(enc_pass) != 2 * key_len or len(salt2) != 64:
    return None

  try:
    return (generate_hash(key_len, iter1_default, word, salt1, int(iter1), enc_pass, salt2, int(iter2)), word)
  except ValueError:
    return None
