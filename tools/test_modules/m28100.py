#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string

# Windows Hello PIN (NGC): the PIN is widened to its uppercase hex spelling, run through
# PBKDF2-HMAC-SHA256, widened and hashed again, then folded into a two stage HMAC-SHA512 over the
# DPAPI-NG masterkey, the stored hmac, a magic value and the verify blob.

MAGIC_DEFAULT = "785435725a573571565662727670754100"


def module_constraints():
  return [[4, 127], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def module_generate_hash(word, salt, iter=None, mk=None, hmac=None, blob=None, magicv=None):
  if iter is None:
    iter = 10000

  if mk is None:
    mk = random_hex_string(128)

  if hmac is None:
    hmac = random_hex_string(64)

  if blob is None:
    blob = random_hex_string(1384)

  if magicv is None:
    magicv = MAGIC_DEFAULT

  iter = int(iter)

  salt_bin = bytes.fromhex(salt)
  mk_bin = bytes.fromhex(mk)
  hmac_bin = bytes.fromhex(hmac)
  blob_bin = bytes.fromhex(blob)
  magicv_bin = bytes.fromhex(magicv)

  # convert_userpin_to_secretpin: the PIN's lowercase hex spelling, uppercased and UTF-16LE widened
  stage1 = word.hex().encode("utf-16-le").upper()

  stage2 = hashlib.pbkdf2_hmac("sha256", stage1, salt_bin, iter, 32)

  stage3 = stage2.hex().encode("utf-16-le").upper()

  stage4 = hashlib.sha512(stage3).digest()

  masterkey = hashlib.sha1(mk_bin).digest() + b"\x00" * 108

  sub_digest_seed = _xor(masterkey, b"\x36" * 128)
  main_digest_seed = _xor(masterkey, b"\x5c" * 128)

  sub_digest = hashlib.sha512(sub_digest_seed + hmac_bin + magicv_bin + stage4 + blob_bin).digest()

  main_digest = hashlib.sha512(main_digest_seed + sub_digest).digest()

  return "$WINHELLO$*SHA512*%i*%s*%s*%s*%s*%s*%s" % (
    iter, salt_bin.hex(), main_digest.hex(), mk_bin.hex(),
    hmac_bin.hex(), blob_bin.hex(), magicv_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  parts = hash_in.split("*")

  if len(parts) < 9:
    return None

  signature, algo, iter, pin_salt, sign, mk, hmac, verify_blob, magicv = parts[:9]

  if signature != "$WINHELLO$" or algo != "SHA512":
    return None

  if len(pin_salt) != 8 or len(sign) != 128 or len(mk) != 128:
    return None

  if len(hmac) != 64 or len(verify_blob) != 1384:
    return None

  return (module_generate_hash(word, pin_salt, iter, mk, hmac, verify_blob, magicv), word)
