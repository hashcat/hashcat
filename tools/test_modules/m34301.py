#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# KeePass 4 with the AES key derivation function, which is the same database and the same header
# HMAC as m34300 with a different way of getting to the key:
#
#   composite = SHA256(SHA256(password) || keyfile)
#   derived   = SHA256(AES-256-ECB(transform seed) applied `iterations` times to both halves)
#   hmac key  = SHA512(0xff * 8 || SHA512(master seed || derived || 0x01))
#
# The Argon2 fields of the hash carry the AES-KDF UUID and three zeroes.

UUID = "c9d9f39a"

KEYFILE_LEN = 32
HEADER_LEN  = 250


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def _header_hmac(word, keyfile, iterations, master_seed, transform_seed, header):
  composite = hashlib.sha256(hashlib.sha256(word).digest() + keyfile).digest()

  aes = AES.new(transform_seed, AES.MODE_ECB)

  left, right = composite[:16], composite[16:]

  for _ in range(iterations):
    left  = aes.encrypt(left)
    right = aes.encrypt(right)

  derived = hashlib.sha256(left + right).digest()

  final = hashlib.sha512(master_seed + derived + b"\x01").digest()

  return hmac.new(hashlib.sha512(b"\xff" * 8 + final).digest(), header, hashlib.sha256).digest()


def _build(iterations, master_seed, transform_seed, header, header_hmac, keyfile):
  out = "$keepass$*4*%d*%s*0*0*0*%s*%s*%s*%s" % (
    iterations, UUID, master_seed.hex(), transform_seed.hex(), header.hex(), header_hmac.hex())

  if keyfile:
    out += "*1*64*%s" % keyfile.hex()

  return out


def module_generate_hash(word, salt, iterations=None):
  keyfile = random_bytes(KEYFILE_LEN) if random_number(0, 1) else b""

  master_seed    = random_bytes(32)
  transform_seed = random_bytes(32)

  rounds = random_number(20000, 60000)

  header = random_bytes(HEADER_LEN)

  header_hmac = _header_hmac(word, keyfile, rounds, master_seed, transform_seed, header)

  return _build(rounds, master_seed, transform_seed, header, header_hmac, keyfile)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"*")

  if len(parts) not in (11, 14) or parts[0] != b"$keepass$" or parts[1] != b"4":
    return None

  if parts[3].decode("ascii", "replace") != UUID:
    return None

  try:
    rounds         = int(parts[2])
    master_seed    = bytes.fromhex(parts[7].decode("ascii"))
    transform_seed = bytes.fromhex(parts[8].decode("ascii"))
    header         = bytes.fromhex(parts[9].decode("ascii"))
    header_hmac    = bytes.fromhex(parts[10].decode("ascii"))
    keyfile        = bytes.fromhex(parts[13].decode("ascii")) if len(parts) == 14 else b""
  except (UnicodeDecodeError, ValueError):
    return None

  got = _header_hmac(word, keyfile, rounds, master_seed, transform_seed, header)

  if got != header_hmac:
    return None

  return (_build(rounds, master_seed, transform_seed, header, header_hmac, keyfile), word)
