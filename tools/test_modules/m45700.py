#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import os

from Crypto.Cipher import AES


# Jaxx Liberty wallet record: key = PBKDF2-HMAC-SHA256(password, sb, 5000, 32),
# et = AES-256-GCM(key, iv) over the BIP39 entropy hex. A crack is the GCM tag
# matching, which is exact. Hash line: $jaxx$<sb_b64>$<iv_b64>$<ct+tag_b64>

ROUNDS = 5000


def _make_hash(word, salt):
  if isinstance(word, str):
    word = word.encode()

  sb = salt[:16]
  iv = os.urandom(12)

  key = hashlib.pbkdf2_hmac("sha256", word, sb, ROUNDS, 32)

  pt = os.urandom(16).hex().encode()  # entropy hex, 32 chars

  cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
  ct, tag = cipher.encrypt_and_digest(pt)

  return "$jaxx$%s$%s$%s" % (
    base64.b64encode(sb).decode(),
    base64.b64encode(iv).decode(),
    base64.b64encode(ct + tag).decode())


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None):
  if salt is None:
    salt = os.urandom(16)

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if len(salt) < 16:
    salt = salt + os.urandom(16 - len(salt))

  return _make_hash(word, salt)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$jaxx$"):
    return None

  fields = hash_in.split("$")

  if len(fields) != 5:
    return None

  try:
    sb     = base64.b64decode(fields[2])
    iv     = base64.b64decode(fields[3])
    cttag  = base64.b64decode(fields[4])
  except Exception:
    return None

  ct, tag = cttag[:-16], cttag[-16:]

  try:
    key = hashlib.pbkdf2_hmac("sha256", word, sb, ROUNDS, 32)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.decrypt_and_verify(ct, tag)
  except Exception:
    return None

  return (hash_in, word)
