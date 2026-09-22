#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import CAST

from lib import gpg
from lib.test_helpers import random_bytes, random_number

# GPG symmetric secret key protection with CAST5 in CFB. The S2K is SHA-1 either way, but the
# mode has two shapes and a run covers both: iterated and salted, which carries a count, and
# plain salted, which is one SHA-1 over salt and password.

S2K_HASH     = "sha1"
S2K_HASH_ID  = 2
CIPHER_ALGO  = 3
KEY_LEN      = 16
IV_LEN       = 8
MODULUS_SIZE = 4096
BODY_LEN     = 648


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def _cfb(key, iv):
  return CAST.new(key, CAST.MODE_CFB, IV=iv, segment_size=64)


def _key(word, salt, s2k_type, count):
  if s2k_type == gpg.S2K_ITERATED:
    return gpg.s2k_iterated(word, salt, count, KEY_LEN, S2K_HASH)

  return gpg.s2k_salted(word, salt, KEY_LEN, S2K_HASH)


def module_generate_hash(word, salt, iterations=None):
  iterated = random_number(0, 1) == 1

  s2k_type = gpg.S2K_ITERATED if iterated else gpg.S2K_SALTED
  count    = random_number(50000, 60000) if iterated else 0

  salt_raw = random_bytes(8)
  iv       = random_bytes(IV_LEN)

  key  = _key(word, salt_raw, s2k_type, count)
  body = random_bytes(BODY_LEN)

  plain = body + hashlib.sha1(body).digest()

  return gpg.build(_cfb(key, iv).encrypt(plain), MODULUS_SIZE, s2k_type,
                   S2K_HASH_ID, CIPHER_ALGO, iv, count, salt_raw)


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

  if fields["hash_id"] != S2K_HASH_ID or fields["cipher_algo"] != CIPHER_ALGO:
    return None

  if len(fields["iv"]) != IV_LEN:
    return None

  key   = _key(word, fields["salt"], fields["s2k_type"], fields["count"])
  plain = _cfb(key, fields["iv"]).decrypt(fields["data"])

  if len(plain) < 20 or hashlib.sha1(plain[:-20]).digest() != plain[-20:]:
    return None

  digest = gpg.build(_cfb(key, fields["iv"]).encrypt(plain), fields["modulus_size"],
                     fields["s2k_type"], S2K_HASH_ID, CIPHER_ALGO, fields["iv"],
                     fields["count"], fields["salt"])

  return (digest, word)
