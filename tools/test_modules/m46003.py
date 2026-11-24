#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import os

from lib.test_helpers import random_number

try:
  from Crypto.Cipher import ChaCha20_Poly1305
  HAVE_CRYPTO = True
except ImportError:
  HAVE_CRYPTO = False

# Cardano EMIP-003 password encryption. The key is PBKDF2-HMAC-SHA512(password, salt, iters, 32),
# the payload is ChaCha20-Poly1305 (IETF, empty AAD). The envelope is
# salt(32) + nonce(12) + tag(16) + ct. A crack is the Poly1305 tag matching, which is exact.
# Line format: $emip3$iters$hex(envelope)

ITERATIONS = 19162

ENVELOPE_MIN = 60 + 1    # header + 1 byte ct
ENVELOPE_MAX = 60 + 2048


def _make_hash(word, salt, iters, ct_len):
  if isinstance(word, str):
    word = word.encode()

  if not HAVE_CRYPTO:
    return None

  nonce = os.urandom(12)

  key = hashlib.pbkdf2_hmac("sha512", word, salt, iters, 32)

  c = ChaCha20_Poly1305.new(key=key, nonce=nonce)

  secret = os.urandom(ct_len)

  ct, tag = c.encrypt_and_digest(secret)

  return "$emip3$%d$%s" % (iters, (salt + nonce + tag + ct).hex())


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None):
  if salt is None:
    salt = os.urandom(32)

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if len(salt) != 32:
    salt = os.urandom(32)

  return _make_hash(word, salt, ITERATIONS, random_number(1, 128))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$emip3$"):
    return None

  fields = hash_in.split("$")

  if len(fields) != 4:
    return None

  try:
    iters = int(fields[2])
    env = bytes.fromhex(fields[3])
  except ValueError:
    return None

  if len(env) < ENVELOPE_MIN or len(env) > ENVELOPE_MAX:
    return None

  if not HAVE_CRYPTO:
    return None

  salt  = env[:32]
  nonce = env[32:44]
  tag   = env[44:60]
  ct    = env[60:]

  try:
    key = hashlib.pbkdf2_hmac("sha512", word, salt, iters, 32)

    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    c.decrypt_and_verify(ct, tag)
  except Exception:
    return None

  return (hash_in, word)
