#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import json

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, test_iteration_parameters


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
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }


# Dogechain.info wallet, AES-GCM variant. The stored string is
#
#   $dogechain$1*<iterations>*<base64 payload>*<base64 salt>
#
# where the payload is a 12-byte IV, then the 16-byte GCM tag, then the AES-256-GCM
# encrypted wallet, and the salt is 16 bytes. The key is
#
#   PBKDF2-HMAC-SHA256(base64(SHA256(password)), salt, iterations, 32)
#
# so the password is hashed and base64'd into a 44-character string before it ever
# reaches PBKDF2, same as in mode 32500 (the AES-CBC variant). The GCM tag is the
# password check: the kernel recomputes it over the ciphertext and compares.

ITERATIONS_DEFAULT = 5000


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def _key(word, salt_raw, iterations):
  secret = base64.b64encode(hashlib.sha256(word).digest())

  return hashlib.pbkdf2_hmac("sha256", secret, salt_raw, iterations, 32)


def _build(iterations, payload, salt_raw):
  return "$dogechain$1*%d*%s*%s" % (
    iterations, base64.b64encode(payload).decode("ascii"),
    base64.b64encode(salt_raw).decode("ascii"))


def module_generate_hash(word, salt, iterations=None):
  if not iterations or iterations <= 0:
    iterations = ITERATIONS_DEFAULT

  salt_raw = bytes.fromhex(salt)

  # vary the body length with the word length: 17 bytes per step over
  # len(word) % 16 walks all ct%16 residues (including the multiple-of-16
  # GHASH branch), len % 16 == 15 lands at 1023, just under the 1024-byte cap

  pad_len = 160 + 17 * (len(word) % 16)

  if len(word) % 16 == 15:
    pad_len += 608

  body = json.dumps({"guid": random_bytes(16).hex(), "sharedKey": random_bytes(16).hex(),
                     "keys": [{"addr": random_bytes(8).hex(), "priv": random_bytes(32).hex()}]},
                    separators=(",", ":"))
  body = (body + " " * pad_len)[:pad_len]

  iv = random_bytes(12)

  cipher = AES.new(_key(word, salt_raw, iterations), AES.MODE_GCM, nonce=iv)

  ct, tag = cipher.encrypt_and_digest(body.encode("ascii"))

  return _build(iterations, iv + tag + ct, salt_raw)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"*")

  if len(parts) != 4 or parts[0] != b"$dogechain$1":
    return None

  try:
    iterations = int(parts[1])
    payload    = base64.b64decode(parts[2], validate=True)
    salt_raw   = base64.b64decode(parts[3], validate=True)
  except Exception:
    return None

  if len(salt_raw) != 16 or len(payload) < 12 + 16 + 16:
    return None

  iv  = payload[:12]
  tag = payload[12:28]
  ct  = payload[28:]

  cipher = AES.new(_key(word, salt_raw, iterations), AES.MODE_GCM, nonce=iv)

  try:
    cipher.decrypt_and_verify(ct, tag)
  except ValueError:
    return None

  return (_build(iterations, payload, salt_raw), word)
