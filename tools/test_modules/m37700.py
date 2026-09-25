#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import ChaCha20_Poly1305

from lib.test_helpers import random_bytes, random_hex_string

# Cardano Eternl wallet: PBKDF2-HMAC-SHA512 of the password over the 32 byte salt gives a 32 byte
# ChaCha20-Poly1305 key. The line is ETERNL: then salt, 12 byte nonce, 16 byte tag and the 165 byte
# ciphertext, each in hex with no separators. Without a ciphertext to decrypt the plaintext is
# random, so a generated hash is only reproducible through the cross verification, not from a seed.

ITERATIONS = 210012


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, nonce=None, ciphertext=None, tag=None):
  if nonce is None:
    nonce = random_hex_string(24)

  salt_bin = bytes.fromhex(salt)
  nonce_bin = bytes.fromhex(nonce)

  key = hashlib.pbkdf2_hmac("sha512", word, salt_bin, ITERATIONS, 32)

  if ciphertext is not None:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce_bin)
    plaintext = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
  else:
    plaintext = random_bytes(165)

  cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce_bin)
  ciphertext_bin, tag_bin = cipher.encrypt_and_digest(plaintext)

  return "ETERNL:%s%s%s%s" % (
    salt_bin.hex(),
    nonce_bin.hex(),
    tag_bin.hex(),
    ciphertext_bin.hex())


def module_verify_hash(line):
  # The hash carries no colons, so the first ':' past the signature is the password separator.
  idx = line.find(b":", 7)

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[:7] != "ETERNL:":
    return None

  body = hash_in[7:]

  if len(body) != 64 + 24 + 32 + 330:
    return None

  salt = body[:64]
  nonce = body[64:88]
  tag = body[88:120]
  ciphertext = body[120:]

  try:
    for field in (salt, nonce, tag, ciphertext):
      bytes.fromhex(field)
  except ValueError:
    return None

  return (module_generate_hash(word, salt, nonce, ciphertext, tag), word)
