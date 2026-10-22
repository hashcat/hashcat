#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number

# iTunes backup 9.x. PBKDF2-HMAC-SHA1 turns the password into a 32 byte KEK, and the 40 byte WPKY is
# that KEK wrapping a known constant with the RFC 3394 AES key wrap. Verify unwraps the stored WPKY
# and, when the constant comes back, wraps it again, so the printed hash is rebuilt from the file's
# own fields rather than from a fresh random draw.

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
  return [[0, 256], [40, 40], [0, 55], [40, 40], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, wpky_param=None):
  if iterations is None:
    iterations = 10000

  iterations = int(iterations)

  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, 32)

  if wpky_param is not None:
    a, r = _aes_unwrap(key, wpky_param)

    if a == ITUNES_BACKUP_KEY:
      wpky = _aes_wrap(key, a, r)
    else:
      wpky = b"\x00" * 40
  else:
    r = [random_number(0, 18446744073709551615) for _ in range(4)]

    wpky = _aes_wrap(key, ITUNES_BACKUP_KEY, r)

  return "$itunes_backup$*9*%s*%i*%s**" % (wpky.hex(), iterations, salt_bin.hex())


def module_verify_hash(line):
  parts = line.split(b":")

  if len(parts) < 2:
    return None

  hash_in = parts[0].decode(errors="replace")
  word    = parts[1]

  fields = hash_in.split("*")

  if len(fields) < 5:
    return None

  signature, version, wpky_encoded, iterations, salt = fields[0], fields[1], fields[2], fields[3], fields[4]

  if signature != "$itunes_backup$":
    return None

  if version != "9":
    return None

  if len(wpky_encoded) != 80:
    return None

  wpky = bytes.fromhex(wpky_encoded)

  return (module_generate_hash(word, salt, int(iterations), wpky), word)
