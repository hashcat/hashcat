#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import gpg

# GPG symmetric secret key protection, S2K iterated and salted, AES-128 or AES-256 in CFB.
# Integrity is the trailing SHA-1 over the decrypted data, secret key usage 254, which is what
# module_17010.c check_decoded_data () verifies.
#
# The S2K hash is what separates this mode from m17010 (SHA-1), m17020 (SHA-512) and m17030
# (SHA-256). S2K_HASH_ID is the OpenPGP hash algorithm id the parser requires.

S2K_HASH    = "sha1"
S2K_HASH_ID = 2


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return gpg.aes_cfb_generate(word, S2K_HASH, S2K_HASH_ID)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    fields = gpg.parse(hash_in.decode("ascii"))
  except UnicodeDecodeError:
    return None

  if fields is None:
    return None

  digest = gpg.aes_cfb_verify(word, fields, S2K_HASH, S2K_HASH_ID)

  if digest is None:
    return None

  return (digest, word)
