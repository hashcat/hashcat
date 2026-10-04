#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# Open Document Format (ODF) 1.2. The password is SHA-256 hashed, that digest is the PBKDF2-HMAC-SHA1
# input for a 32 byte AES key, and the file blob is AES-CBC. The stored checksum is SHA-256 of the
# plaintext, so verify decrypts and re-encrypts from the file's own fields.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iv=None, plain=None):
  iters = 100000 if iterations is None else int(iterations)

  if iv is None:
    iv = random_hex_string(2 * 16)

  if plain is None:
    plain = random_hex_string(2 * 1024)

  b_iv    = bytes.fromhex(iv)
  b_salt  = bytes.fromhex(salt)
  b_plain = bytes.fromhex(plain)

  pass_hash = hashlib.sha256(word).digest()
  key       = hashlib.pbkdf2_hmac("sha1", pass_hash, b_salt, iters, 32)

  b_cipher  = AES.new(key, AES.MODE_CBC, b_iv).encrypt(b_plain)
  checksum  = hashlib.sha256(b_plain).hexdigest()

  return "$odf$*1*1*%d*32*%s*16*%s*16*%s*0*%s" % (iters, checksum, iv, salt, b_cipher.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  data = hash_in.split("*")

  if len(data) != 12:
    return None

  signature, cipher_type, cs_type, iters, cs_len = data[0:5]
  iv_len, iv, salt_len, salt, unused, cipher      = data[6], data[7], data[8], data[9], data[10], data[11]

  if signature != "$odf$":
    return None

  if cipher_type != "1" or cs_type != "1" or cs_len != "32":
    return None

  if iv_len != "16" or salt_len != "16" or unused != "0":
    return None

  b_iv     = bytes.fromhex(iv)
  b_salt   = bytes.fromhex(salt)
  b_cipher = bytes.fromhex(cipher)

  pass_hash = hashlib.sha256(word).digest()
  key       = hashlib.pbkdf2_hmac("sha1", pass_hash, b_salt, int(iters), 32)

  b_plain = AES.new(key, AES.MODE_CBC, b_iv).decrypt(b_cipher)

  return (module_generate_hash(word, salt, iters, iv, b_plain.hex()), word)
