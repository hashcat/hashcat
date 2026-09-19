#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import json

from Crypto.Cipher import AES

from test_helpers import random_bytes

# Dogechain.info wallet. The stored string is
#
#   $dogechain$0*<iterations>*<base64 payload>*<base64 salt>
#
# where the payload is a 16-byte IV followed by the AES-256-CBC encrypted wallet, 240 bytes in
# total, and the salt is 16 bytes. The key is
#
#   PBKDF2-HMAC-SHA256(base64(SHA256(password)), salt, iterations, 32)
#
# so the password is hashed and base64'd into a 44-character string before it ever reaches PBKDF2.
#
# There is no MAC: the kernel decides a password is right when the decrypted wallet is all ASCII.
# It skips the final block while checking, because the padding is ISO 10126, which is random bytes
# with a length byte at the end and would fail an ASCII test on its own. The oracle matches that by
# making the plaintext exactly 208 ASCII bytes, so the padding takes up a whole block of its own
# and every byte the kernel looks at is ASCII.

ITERATIONS_DEFAULT = 5000
BODY_LEN           = 208
PAD_LEN            = 16


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def _key(word, salt_raw, iterations):
  secret = base64.b64encode(hashlib.sha256(word).digest())

  return hashlib.pbkdf2_hmac("sha256", secret, salt_raw, iterations, 32)


def _build(iterations, payload, salt_raw):
  return "$dogechain$0*%d*%s*%s" % (
    iterations, base64.b64encode(payload).decode("ascii"),
    base64.b64encode(salt_raw).decode("ascii"))


def module_generate_hash(word, salt, iterations=None):
  if not iterations or iterations <= 0:
    iterations = ITERATIONS_DEFAULT

  salt_raw = bytes.fromhex(salt)

  body = json.dumps({"guid": random_bytes(16).hex(), "sharedKey": random_bytes(16).hex()},
                    separators=(",", ":"))
  body = (body + " " * BODY_LEN)[:BODY_LEN]

  padded = body.encode("ascii") + random_bytes(PAD_LEN - 1) + bytes([PAD_LEN])

  iv = random_bytes(16)

  payload = iv + AES.new(_key(word, salt_raw, iterations), AES.MODE_CBC, iv=iv).encrypt(padded)

  return _build(iterations, payload, salt_raw)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"*")

  if len(parts) != 4 or parts[0] != b"$dogechain$0":
    return None

  try:
    iterations = int(parts[1])
    payload    = base64.b64decode(parts[2], validate=True)
    salt_raw   = base64.b64decode(parts[3], validate=True)
  except Exception:
    return None

  if len(salt_raw) != 16 or len(payload) != 16 + BODY_LEN + PAD_LEN:
    return None

  iv = payload[:16]

  padded = AES.new(_key(word, salt_raw, iterations), AES.MODE_CBC, iv=iv).decrypt(payload[16:])

  # what the kernel looks at: everything but the final block has to be ASCII

  if max(padded[:BODY_LEN]) > 0x7f:
    return None

  return (_build(iterations, payload, salt_raw), word)
