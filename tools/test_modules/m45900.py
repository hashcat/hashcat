#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import os
import re

from Crypto.Cipher import AES
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ec

from lib.test_helpers import runtime_iteration_limit


# Sparrow Wallet SPRW1 container (H2 2.x MVStore, XTS-AES-128 file encryption):
#   priv = Argon2id(utf8(pw), argonSalt16, t=10, m=256MiB, p=4, 32B, v=0x13)
#   pub  = secp256k1 compressed pubkey(priv)
#   aes  = PBKDF2-HMAC-SHA256(utf16be(lowhex(pub)), h2salt8, 10, 16B)
#   ok   = XTS-AES-128 decrypt of unit 0 shows the MVStore store header
#          ("H:2,block:...,...")
# Hash line: $sparrow$1$<argonSalt16 hex>$<h2salt8 hex>$<first 64B of unit0 ct hex>

ARGON_TIME = 10
ARGON_MEM  = 262144  # 256 MiB in KiB
ARGON_PAR  = 4

TEST_LIMIT = runtime_iteration_limit()

if TEST_LIMIT is not None:
  if TEST_LIMIT < 4 or TEST_LIMIT % 4 != 0:
    raise ValueError("Sparrow runtime limits must be multiples of four")

  ARGON_TIME = min(ARGON_TIME, TEST_LIMIT // 4)
  ARGON_MEM = min(ARGON_MEM, 4096)


def _xts_encrypt_unit0(key, pt):
  # H2 XTS variant: single AES-128 key, tweak = AES-ECB-enc(key, LE128(unit)),
  # GF(2^128) feedback 0x87 per 16-byte block. pt must be a multiple of 16.
  cipher = AES.new(key, AES.MODE_ECB)
  tweak = cipher.encrypt(b"\x00" * 16)

  ct = bytearray()

  for i in range(0, len(pt), 16):
    blk = bytes(a ^ b for a, b in zip(pt[i:i + 16], tweak))
    blk = bytes(a ^ b for a, b in zip(cipher.encrypt(blk), tweak))
    ct += blk

    ci = 0
    tw = bytearray(tweak)

    for j in range(16):
      co = tw[j] >> 7
      tw[j] = ((tw[j] << 1) | ci) & 0xff
      ci = co

    if ci:
      tw[0] ^= 0x87

    tweak = bytes(tw)

  return bytes(ct)


def _make_ct(word, argon_salt, h2salt):
  if isinstance(word, str):
    word = word.encode()

  priv = hash_secret_raw(word, argon_salt, time_cost=ARGON_TIME,
                         memory_cost=ARGON_MEM, parallelism=ARGON_PAR,
                         hash_len=32, type=Type.ID, version=19)

  nums = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256K1()).public_key().public_numbers()
  pub = bytes([0x02 | (nums.y & 1)]) + nums.x.to_bytes(32, "big")

  pw16 = pub.hex().encode("utf-16-be")

  key = hashlib.pbkdf2_hmac("sha256", pw16, h2salt, 10, dklen=16)

  # synthetic but shape-correct MVStore store header
  pt = b"H:2,block:2,blockSize:1000,chunk:1,created:19a7c2f,fletcher:3afc"
  pt = pt + b"\x00" * (64 - len(pt))

  return _xts_encrypt_unit0(key, pt)


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
    'runtime': {'limit': 8, 'compiled_cost': True},
  }


def module_generate_hash(word, salt=None):
  if salt is None:
    salt = os.urandom(16)

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  argon_salt = salt
  h2salt = os.urandom(8)

  ct = _make_ct(word, argon_salt, h2salt)

  return "$sparrow$1$%s$%s$%s" % (argon_salt.hex(), h2salt.hex(), ct.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$sparrow$1$"):
    return None

  fields = hash_in.split("$")

  if len(fields) != 6:
    return None

  try:
    argon_salt = bytes.fromhex(fields[3])
    h2salt     = bytes.fromhex(fields[4])
    ct         = bytes.fromhex(fields[5])
  except ValueError:
    return None

  if len(argon_salt) != 16 or len(h2salt) != 8 or len(ct) != 64:
    return None

  priv = hash_secret_raw(word, argon_salt, time_cost=ARGON_TIME,
                         memory_cost=ARGON_MEM, parallelism=ARGON_PAR,
                         hash_len=32, type=Type.ID, version=19)

  nums = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256K1()).public_key().public_numbers()
  pub = bytes([0x02 | (nums.y & 1)]) + nums.x.to_bytes(32, "big")

  pw16 = pub.hex().encode("utf-16-be")

  key = hashlib.pbkdf2_hmac("sha256", pw16, h2salt, 10, dklen=16)

  cipher = AES.new(key, AES.MODE_ECB)
  tweak = cipher.encrypt(b"\x00" * 16)
  pt = bytes(a ^ b for a, b in
             zip(cipher.decrypt(bytes(x ^ y for x, y in zip(ct[:16], tweak))), tweak))

  if not (all(0x20 <= b <= 0x7e for b in pt)
          and re.match(rb"^[A-Za-z]{1,12}:[0-9a-fA-F]{1,16}(,|$)", pt)):
    return None

  return (hash_in, word)
