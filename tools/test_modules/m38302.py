#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import DES3

from lib.test_helpers import random_bytes, test_iteration_parameters


def module_test_properties():
  # Salt is 40 hex characters (20 bytes). The runner emits this many characters.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [40, 40],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 2048}},
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }


# Apple DMG (cdsaencr v1, $dmg$1). PBKDF2-HMAC-SHA1 derives a 32-byte key of which the first
# 24 bytes form a 3DES key. Each wrapped key blob is verified in two stages: 3DES-CBC decrypt
# with the fixed wrap IV 4adda22c79e82105, PKCS#7 (block 8) check, reverse the buffer, then a
# second 3DES-CBC decrypt keyed with the first 8 bytes as IV, and a final PKCS#7 check.
# Both blobs (wrapped AES key, wrapped HMAC key) must verify.

SIGNATURE = "$dmg$1"
WRAP_IV   = bytes.fromhex("4adda22c79e82105")


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def _pbkdf2(word, salt_bin, iterations):
  return hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, 32)


def _pkcs7_unpad(data):
  if len(data) == 0:
    return None
  pad = data[-1]
  if pad < 1 or pad > 8 or pad > len(data):
    return None
  if data[-pad:] != bytes([pad]) * pad:
    return None
  return data[:-pad]


def _unwrap(dk, blob):
  if len(blob) < 16 or len(blob) % 8 != 0:
    return None
  t1 = DES3.new(dk[:24], DES3.MODE_CBC, iv=WRAP_IV).decrypt(blob)
  t1 = _pkcs7_unpad(t1)
  if t1 is None or len(t1) < 16 or len(t1) % 8 != 0:
    return None
  t2 = t1[::-1]
  t3 = DES3.new(dk[:24], DES3.MODE_CBC, iv=t2[:8]).decrypt(t2[8:])
  return _pkcs7_unpad(t3)


def _wrap(dk, key_material):
  pad = 8 - (len(key_material) % 8)
  p2 = key_material + bytes([pad]) * pad
  iv8 = random_bytes(8)
  c2 = DES3.new(dk[:24], DES3.MODE_CBC, iv=iv8).encrypt(p2)
  t1 = (iv8 + c2)[::-1]
  t1 += b"\x08" * 8  # reversed length is a multiple of 8, so the pad is a full block
  return DES3.new(dk[:24], DES3.MODE_CBC, iv=WRAP_IV).encrypt(t1)


def _blob_ok(word, salt_bin, iterations, blob_bin):
  dk = _pbkdf2(word, salt_bin, iterations)
  return _unwrap(dk, blob_bin) is not None


def module_generate_hash(word, salt, iterations=None, keyblob1=None, keyblob2=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt = salt[:len(salt) - (len(salt) % 2)]

  salt_bin = bytes.fromhex(salt)

  dk = _pbkdf2(word, salt_bin, iterations)

  # reuse supplied blobs only when they actually belong to this candidate,
  # otherwise emit fresh blobs so a wrong word cannot round-trip to the input hash
  if keyblob1 is not None and _blob_ok(word, salt_bin, iterations, bytes.fromhex(keyblob1)):
    blob1_bin = bytes.fromhex(keyblob1)
  else:
    blob1_bin = _wrap(dk, random_bytes(16))

  if keyblob2 is not None and _blob_ok(word, salt_bin, iterations, bytes.fromhex(keyblob2)):
    blob2_bin = bytes.fromhex(keyblob2)
  else:
    blob2_bin = _wrap(dk, random_bytes(20))

  return "%s*%d*%s*%d*%s*%d*%s*%d" % (SIGNATURE, len(salt_bin), salt_bin.hex(),
                                      len(blob1_bin), blob1_bin.hex(),
                                      len(blob2_bin), blob2_bin.hex(), iterations)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith(SIGNATURE):
    return None

  fields = hash_in.split("*")

  if len(fields) != 7 and len(fields) != 8:
    return None

  # $dmg$1 * saltlen * salt * len1 * blob1 * len2 * blob2 * [iterations]
  salt       = fields[2]
  keyblob1   = fields[4]
  keyblob2   = fields[6]
  iterations = fields[7] if len(fields) == 8 else 1000

  return (module_generate_hash(word, salt, iterations, keyblob1, keyblob2), word)
