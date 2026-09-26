#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import zlib

from Crypto.Cipher import AES

from lib import secp256k1
from lib.test_helpers import random_bytes, random_number, random_string

# Electrum wallet, salt type 5. The wallet is a JSON document, deflated and then encrypted, and the
# key comes out of a Diffie-Hellman between the password and an ephemeral public key the hash
# carries:
#
#   scalar = PBKDF2-HMAC-SHA512 (password, "", 1024, 64)
#   key    = sha512 (compress (scalar * ephemeral_pubkey))
#
# The first 16 bytes of that key are the IV, the next 16 the AES key and the last 32 the HMAC key.
#
# Only the first 1024 bytes of the ciphertext go into the hash, so the MAC cannot be recomputed from
# it and hashcat does not try: m21800-pure.cl inflates what those bytes decrypt to and looks for the
# opening of the document. The payload is drawn large enough that 1024 bytes of it are still a
# deflate stream with something in it.

SIGNATURE = "$electrum$5*"

AES_LEN = 1024

DATA_MIN = 16384
DATA_MAX = DATA_MIN + int(DATA_MIN * 1.30)

OPENINGS = (b"{\n    \"", b"{\r\n    \"")


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _key(word, pubkey):
  point = secp256k1.decompress(pubkey)

  if point is None:
    return None

  scalar = int.from_bytes(hashlib.pbkdf2_hmac("sha512", word, b"", 1024, 64), "big")

  shared = secp256k1.mul(scalar, point)

  if shared is None:
    return None

  return hashlib.sha512(secp256k1.compress(shared)).digest()


def _payload():
  # The hash keeps the first 1024 bytes of ciphertext, so the deflated wallet has to reach at least
  # that far. A draw in this range compresses to more than ten times it, and the loop is here as the
  # guard on that rather than as the expected path.

  while True:
    opening = OPENINGS[random_number(0, 1)]

    body = random_string(random_number(DATA_MIN, DATA_MAX) - len(opening))

    data = zlib.compress(opening + body.encode("ascii"), 6)

    if len(data) > AES_LEN:
      return data


def _pad(data):
  n = 16 - (len(data) % 16)

  return data + bytes([n]) * n


def module_generate_hash(word, salt, iterations=None):
  while True:
    pubkey = bytes([2 + random_number(0, 1)]) + random_bytes(32)

    key = _key(word, pubkey)

    if key is not None:
      break

  data = AES.new(key[16:32], AES.MODE_CBC, iv=key[:16]).encrypt(_pad(_payload()))

  mac = hmac.new(key[32:], data, hashlib.sha256).hexdigest()

  return "%s%s*%s*%s" % (SIGNATURE, pubkey.hex(), data[:AES_LEN].hex(), mac)


def _accepts(word, line):
  if not line.startswith(SIGNATURE):
    return False

  t = line[len(SIGNATURE):].split("*")

  if len(t) != 3:
    return False

  try:
    pubkey = bytes.fromhex(t[0])
    data   = bytes.fromhex(t[1])
  except ValueError:
    return False

  if len(data) != AES_LEN:
    return False

  key = _key(word, pubkey)

  if key is None:
    return False

  plain = AES.new(key[16:32], AES.MODE_CBC, iv=key[:16]).decrypt(data)

  try:
    # the stream is cut off at 1024 bytes of ciphertext, so this ends early and that is not an error

    out = zlib.decompressobj().decompress(plain)
  except zlib.error:
    return False

  return out.startswith(OPENINGS[0]) or out.startswith(OPENINGS[1])


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    text = hash_in.decode("ascii")
  except UnicodeDecodeError:
    return None

  if _accepts(word, text) is False:
    return None

  return (text, word)
