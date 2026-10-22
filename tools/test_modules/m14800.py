#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# iTunes backup 10.x. Same RFC 3394 AES key wrap as -m 14700, with an extra PBKDF2-HMAC-SHA256 pass
# over a second salt (DPSL) feeding the SHA1 pass that derives the KEK.

ITUNES_BACKUP_KEY = 12008468691120727718

MASK64 = 0xffffffffffffffff


def _aes_wrap(key, a, r):
  cipher = AES.new(key, AES.MODE_ECB)

  k = len(r)
  r = list(r)

  for j in range(6):
    for i in range(1, k + 1):
      idx = i - 1

      t = cipher.encrypt(a.to_bytes(8, "big") + r[idx].to_bytes(8, "big"))

      a  = int.from_bytes(t[0:8], "big")
      a ^= (k * j + i)

      r[idx] = int.from_bytes(t[8:16], "big")

  out = a.to_bytes(8, "big")

  for value in r[:k]:
    out += value.to_bytes(8, "big")

  return out


def _aes_unwrap(key, wpky):
  cipher = AES.new(key, AES.MODE_ECB)

  b = [int.from_bytes(wpky[i * 8:i * 8 + 8], "big") for i in range(len(wpky) // 8)]

  k = len(b) - 1
  r = [b[i + 1] for i in range(k)]

  a = b[0]

  for j in range(5, -1, -1):
    for i in range(k, 0, -1):
      idx = i - 1

      t = cipher.decrypt(((a ^ (k * j + i)) & MASK64).to_bytes(8, "big") + r[idx].to_bytes(8, "big"))

      a      = int.from_bytes(t[0:8], "big")
      r[idx] = int.from_bytes(t[8:16], "big")

  return a, r


def module_constraints():
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, wpky_param=None, dpic=None, dpsl=None):
  if iterations is None:
    iterations = 10000

  iterations = int(iterations)

  if dpic is None:
    dpic = 1000

  dpic = int(dpic)

  # drawn here, at the same point perl fills the default argument, so a seeded run draws it in the
  # same order as the R values below

  if dpsl is None:
    dpsl = random_bytes(20)

  salt_bin = bytes.fromhex(salt)

  key_dpsl = hashlib.pbkdf2_hmac("sha256", word, dpsl, dpic, 32)

  key = hashlib.pbkdf2_hmac("sha1", key_dpsl, salt_bin, iterations, 32)

  if wpky_param is not None:
    a, r = _aes_unwrap(key, wpky_param)

    if a == ITUNES_BACKUP_KEY:
      wpky = _aes_wrap(key, a, r)
    else:
      wpky = b"\x00" * 40
  else:
    r = [random_number(0, 18446744073709551615) for _ in range(4)]

    wpky = _aes_wrap(key, ITUNES_BACKUP_KEY, r)

  return "$itunes_backup$*10*%s*%i*%s*%i*%s" % (wpky.hex(), iterations, salt_bin.hex(), dpic, dpsl.hex())


def module_verify_hash(line):
  parts = line.split(b":")

  if len(parts) < 2:
    return None

  hash_in = parts[0].decode(errors="replace")
  word    = parts[1]

  fields = hash_in.split("*")

  if len(fields) < 7:
    return None

  signature, version, wpky_encoded, iterations, salt, dpic, dpsl_encoded = fields[0:7]

  if signature != "$itunes_backup$":
    return None

  if version != "10":
    return None

  if len(wpky_encoded) != 80:
    return None

  wpky = bytes.fromhex(wpky_encoded)
  dpsl = bytes.fromhex(dpsl_encoded)

  return (module_generate_hash(word, salt, int(iterations), wpky, int(dpic), dpsl), word)
