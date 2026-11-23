#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os

from lib.test_helpers import random_number

try:
  from argon2.low_level import hash_secret_raw, Type
  HAVE_ARGON2 = True
except ImportError:
  HAVE_ARGON2 = False

try:
  from Crypto.Cipher import ChaCha20_Poly1305
  HAVE_CRYPTO = True
except ImportError:
  HAVE_CRYPTO = False

# Lace / Nami SBV1 secret box. The key is Argon2id(password, salt, m=19456KiB, t=2, p=1, 32),
# the payload is ChaCha20-Poly1305 (IETF) with the 48-byte envelope header as AAD:
# "SBV1"(4) + salt(32) + nonce(12), then ct, then the 16-byte Poly1305 tag.
# A crack is the tag matching, which is exact, not heuristic.
# Line format: $sbv1$hex(full envelope)

ARGON_M = 19456  # KiB
ARGON_T = 2
ARGON_P = 1

ENVELOPE_MIN = 48 + 17  # header + 1 byte ct + tag
ENVELOPE_MAX = 48 + 2048 + 16


def _make_hash(word, salt):
  if isinstance(word, str):
    word = word.encode()

  if not (HAVE_ARGON2 and HAVE_CRYPTO):
    return None

  nonce = os.urandom(12)

  key = hash_secret_raw(word, salt, time_cost=ARGON_T, memory_cost=ARGON_M,
                        parallelism=ARGON_P, hash_len=32, type=Type.ID, version=19)

  header = b"SBV1" + salt + nonce

  c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
  c.update(header)

  secret = os.urandom(random_number(1, 128))

  ct, tag = c.encrypt_and_digest(secret)

  return "$sbv1$" + (header + ct + tag).hex()


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

  return _make_hash(word, salt)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$sbv1$"):
    return None

  try:
    env = bytes.fromhex(hash_in[6:])
  except ValueError:
    return None

  if len(env) < ENVELOPE_MIN or len(env) > ENVELOPE_MAX:
    return None

  if env[:4] != b"SBV1":
    return None

  if not (HAVE_ARGON2 and HAVE_CRYPTO):
    return None

  salt  = env[4:36]
  nonce = env[36:48]
  body  = env[48:]
  ct, tag = body[:-16], body[-16:]

  try:
    key = hash_secret_raw(word, salt, time_cost=ARGON_T, memory_cost=ARGON_M,
                          parallelism=ARGON_P, hash_len=32, type=Type.ID, version=19)

    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(env[:48])

    c.decrypt_and_verify(ct, tag)
  except Exception:
    return None

  return (hash_in, word)
