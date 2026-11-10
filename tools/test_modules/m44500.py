#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Tezos presale (ICO) wallet. The PBKDF2-HMAC-SHA512 key is the mnemonic and the salt is
# "mnemonic" || email || password, so the candidate sits inside the HMAC message. The first 32
# bytes of the 64 byte derived key seed an ed25519 key pair and the tz1 address payload is
# BLAKE2b-160 of the public key, stored with its 2 byte a19f prefix in hex. The salt the module
# is handed becomes the mnemonic, the email is drawn at random and is recovered from the hash
# line on verification.

ITERATIONS = 2048

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sha256(b):
  return hashlib.sha256(b).digest()


def _b58enc(b):
  n = int.from_bytes(b, "big")
  s = ""

  while n > 0:
    n, r = divmod(n, 58)
    s = B58[r] + s

  for c in b:
    if c == 0:
      s = "1" + s
    else:
      break

  return s


def _b58check_enc(b):
  return _b58enc(b + _sha256(_sha256(b))[:4])


def _tz1(pkh):
  return _b58check_enc(b"\x06\xa1\x9f" + pkh)


def _derive(word, mnemonic, email):
  if isinstance(word, str):
    word = word.encode("utf-8")

  salt = b"mnemonic" + email.encode("utf-8") + word

  seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, ITERATIONS, 64)[:32]

  priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
  pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

  return hashlib.blake2b(pub, digest_size=20).digest()


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [1, 128],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None, email=None):
  mnemonic = salt.decode("utf-8") if isinstance(salt, bytes) else salt

  if email is None:
    # the module takes 1..255 bytes of email: tie the length to the edge lengths being run, so
    # the edge cells cross the 128 byte block boundary of the HMAC update and reach the maximum

    email_len = 1 + (2 * len (mnemonic) + len (word)) % 255

    suffix = "@e.co"

    if email_len > len (suffix):
      email = "a" * (email_len - len (suffix)) + suffix
    else:
      email = "a" * email_len

  pkh = _derive(word, mnemonic, email)

  return "$tezos$1*2048*%s*%s*%s*a19f%s" % (mnemonic, email, _tz1(pkh), pkh.hex())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  fields = hash_in.split("*")

  if len(fields) != 6:
    return None

  sig, iters, mnemonic, email, address, pkh_hex = fields

  if sig != "$tezos$1" or iters != "2048":
    return None

  if not address.startswith("tz1") or len(address) != 36:
    return None

  if pkh_hex[:4] != "a19f" or len(pkh_hex) != 44:
    return None

  try:
    bytes.fromhex(pkh_hex)
  except ValueError:
    return None

  return (module_generate_hash(word, mnemonic, email=email), word)
