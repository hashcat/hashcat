#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from argon2.low_level import Type, hash_secret_raw

from test_helpers import random_bytes, random_number

# KeePass 4 with the Argon2 KDF. What hashcat verifies is the HMAC-SHA256 over the database
# header, and the chain to its key is
#
#   composite = SHA256(SHA256(password) || keyfile)
#   derived   = Argon2(composite, salt = transform seed, t, m, p)
#   hmac key  = SHA512(0xff * 8 || SHA512(master seed || derived || 0x01))
#
# The keyfile is present on half the candidates, and the Argon2 variant alternates between d and
# id, because the hash carries the variant as a UUID and the kernel has a path for each.

UUIDS = {"ef636ddf": Type.D, "9e298b19": Type.ID}

ARGON2_VERSION = 19
KEYFILE_LEN    = 32
HEADER_LEN     = 253


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def _header_hmac(word, keyfile, uuid, time_cost, memory_kib, parallelism, master_seed,
                 transform_seed, header):
  composite = hashlib.sha256(hashlib.sha256(word).digest() + keyfile).digest()

  derived = hash_secret_raw(secret=composite, salt=transform_seed, time_cost=time_cost,
                            memory_cost=memory_kib, parallelism=parallelism, hash_len=32,
                            type=UUIDS[uuid], version=ARGON2_VERSION)

  final = hashlib.sha512(master_seed + derived + b"\x01").digest()

  return hmac.new(hashlib.sha512(b"\xff" * 8 + final).digest(), header, hashlib.sha256).digest()


def _build(time_cost, uuid, memory_kib, parallelism, master_seed, transform_seed, header,
           header_hmac, keyfile):
  out = "$keepass$*4*%d*%s*%d*%d*%d*%s*%s*%s*%s" % (
    time_cost, uuid, memory_kib * 1024, ARGON2_VERSION, parallelism,
    master_seed.hex(), transform_seed.hex(), header.hex(), header_hmac.hex())

  if keyfile:
    out += "*1*64*%s" % keyfile.hex()

  return out


def module_generate_hash(word, salt, iterations=None):
  keyfile = random_bytes(KEYFILE_LEN) if random_number(0, 1) else b""

  master_seed    = random_bytes(32)
  transform_seed = random_bytes(32)

  time_cost   = random_number(1, 8)
  memory_kib  = 1 << random_number(12, 18)
  parallelism = random_number(1, 8)

  header = random_bytes(HEADER_LEN)

  uuid = sorted(UUIDS)[random_number(0, len(UUIDS) - 1)]

  header_hmac = _header_hmac(word, keyfile, uuid, time_cost, memory_kib, parallelism,
                             master_seed, transform_seed, header)

  return _build(time_cost, uuid, memory_kib, parallelism, master_seed, transform_seed, header,
                header_hmac, keyfile)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"*")

  if len(parts) not in (11, 14) or parts[0] != b"$keepass$" or parts[1] != b"4":
    return None

  try:
    time_cost      = int(parts[2])
    uuid           = parts[3].decode("ascii")
    memory_bytes   = int(parts[4])
    parallelism    = int(parts[6])
    master_seed    = bytes.fromhex(parts[7].decode("ascii"))
    transform_seed = bytes.fromhex(parts[8].decode("ascii"))
    header         = bytes.fromhex(parts[9].decode("ascii"))
    header_hmac    = bytes.fromhex(parts[10].decode("ascii"))
    keyfile        = bytes.fromhex(parts[13].decode("ascii")) if len(parts) == 14 else b""
  except (UnicodeDecodeError, ValueError):
    return None

  if uuid not in UUIDS or int(parts[5]) != ARGON2_VERSION:
    return None

  got = _header_hmac(word, keyfile, uuid, time_cost, memory_bytes // 1024, parallelism,
                     master_seed, transform_seed, header)

  if got != header_hmac:
    return None

  return (_build(time_cost, uuid, memory_bytes // 1024, parallelism, master_seed, transform_seed,
                 header, header_hmac, keyfile), word)
