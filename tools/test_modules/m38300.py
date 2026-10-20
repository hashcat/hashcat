#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# Apple DMG (encrcdsa v2, $dmg$3). PBKDF2-HMAC-SHA1 derives a 24-byte KEK; the 64-byte key blob is
# the AES-192-CBC wrap of the volume keys. A password is accepted when CBC-decrypting the LAST blob
# block (AES_decrypt(block[3]) XOR block[2]) yields "CKIE" at bytes 4..7, 0x00 at byte 8 and PKCS#7
# padding of length 7 in the final 7 bytes, so the generated blob places that marker in the last
# plaintext block.

SIGNATURE    = "$dmg$3"
KEY_LEN      = 24   # AES-192 KEK
ITER_DEFAULT = 2048


def module_constraints():
  # salt is 40 hex characters (20 bytes); the runner emits this many characters
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def _pbkdf2(word, salt_bin, iterations):
  return hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, KEY_LEN)


def _marker_ok(word, salt_bin, iterations, blob_bin):
  # derive the KEK from the candidate and CBC-decrypt the last blob block
  # (previous ciphertext block is the CBC IV), then check the CKIE marker.
  if len(blob_bin) != 64:
    return False
  key = _pbkdf2(word, salt_bin, iterations)
  last = AES.new(key, AES.MODE_CBC, blob_bin[32:48]).decrypt(blob_bin[48:64])
  return last[4:8] == b"CKIE" and last[8:9] == b"\x00" and last[9:16] == b"\x07" * 7


def _build_blob(word, salt_bin, iterations):
  key = _pbkdf2(word, salt_bin, iterations)

  # last plaintext block = [4-byte prefix]["CKIE"][0x00][0x07 * 7] (what the kernel checks)
  last_block = random_bytes(4) + b"CKIE" + b"\x00" + b"\x07" * 7

  # first 48 bytes stand in for the opaque wrapped volume keys
  plain_bin = random_bytes(48) + last_block

  iv_bin = random_bytes(16)

  return AES.new(key, AES.MODE_CBC, iv_bin).encrypt(plain_bin)


def module_generate_hash(word, salt, iterations=None, keyblob=None):
  iterations = ITER_DEFAULT if iterations is None else int(iterations)

  salt_bin = bytes.fromhex(salt)

  # reuse a supplied blob only when it actually belongs to this candidate,
  # otherwise emit a fresh blob so a wrong word cannot round-trip to the input hash
  if keyblob is not None and _marker_ok(word, salt_bin, iterations, bytes.fromhex(keyblob)):
    blob_bin = bytes.fromhex(keyblob)
  else:
    blob_bin = _build_blob(word, salt_bin, iterations)

  return "%s*%d*%s*192*%d*%s*%d" % (SIGNATURE, len(salt_bin), salt_bin.hex(),
                                    len(blob_bin), blob_bin.hex(), iterations)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith(SIGNATURE):
    return None

  fields = hash_in.split("*")

  if len(fields) != 7:
    return None

  # $dmg$3 * saltlen * salt * keybits * bloblen * keyblob * iterations
  salt       = fields[2]
  keyblob    = fields[5]
  iterations = fields[6]

  return (module_generate_hash(word, salt, iterations, keyblob), word)
