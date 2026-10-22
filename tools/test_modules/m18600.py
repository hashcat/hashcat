#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import Blowfish

from lib.test_helpers import random_hex_string

# OpenDocument Format 1.1 (SHA-1, Blowfish). PBKDF2-HMAC-SHA1 over sha1(password) makes a Blowfish
# key, and the document body is Blowfish-CFB encrypted; the sha1 of the plaintext is the check.


def module_constraints():
  return [[0, 51], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iv=None, plain=None):
  iterations = 100000 if iterations is None else int(iterations)
  iv = random_hex_string(2 * 8) if iv is None else iv
  plain = random_hex_string(2 * 1024) if plain is None else plain

  b_iv = bytes.fromhex(iv)
  b_salt = bytes.fromhex(salt)
  b_plain = bytes.fromhex(plain)

  pass_hash = hashlib.sha1(word).digest()
  key = hashlib.pbkdf2_hmac("sha1", pass_hash, b_salt, iterations, 16)

  # Crypt::Mode::CFB feeds back a whole block, so this is CFB-64 for Blowfish, not the byte wise CFB8.

  b_cipher = Blowfish.new(key, Blowfish.MODE_CFB, b_iv, segment_size=64).encrypt(b_plain)

  cipher = b_cipher.hex()
  checksum = hashlib.sha1(b_plain).hexdigest()

  return "$odf$*0*0*%s*16*%s*8*%s*16*%s*0*%s" % (iterations, checksum, iv, salt, cipher)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("*")

  if len(data) != 12:
    return None

  (signature, cipher_type, cs_type, it, cs_len, cs, iv_len, iv, salt_len, salt, unused,
   cipher) = data

  if signature != "$odf$" or cipher_type != "0" or cs_type != "0" or cs_len != "16" or \
     iv_len != "8" or salt_len != "16" or unused != "0":
    return None

  b_iv = bytes.fromhex(iv)
  b_salt = bytes.fromhex(salt)
  b_cipher = bytes.fromhex(cipher)

  pass_hash = hashlib.sha1(word).digest()
  key = hashlib.pbkdf2_hmac("sha1", pass_hash, b_salt, int(it), 16)

  b_plain = Blowfish.new(key, Blowfish.MODE_CFB, b_iv, segment_size=64).decrypt(b_cipher)

  return (module_generate_hash(word, salt, int(it), iv, b_plain.hex()), word)
