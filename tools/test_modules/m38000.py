#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string

# MikroTik RouterOS 7 verifier. The scalar SHA256(salt + SHA256(user + ":" + pass)) multiplies the
# curve25519 base point, expressed here in short Weierstrass form so a plain double and add works,
# and the x coordinate is mapped back to Montgomery form. The verifier is the first 28 bytes.

P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
A = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
GX = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a
GY = 0x5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14
CONV_TO_M = 0x555555555555555555555555555555555555555555555555555555555552db9c


def point_add(p1, p2):
  if p1 is None:
    return p2

  if p2 is None:
    return p1

  x1, y1 = p1
  x2, y2 = p2

  if x1 == x2 and (y1 + y2) % P == 0:
    return None

  if x1 == x2 and y1 == y2:
    lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
  else:
    lam = (y2 - y1) * pow(x2 - x1, -1, P) % P

  x3 = (lam * lam - x1 - x2) % P
  y3 = (lam * (x1 - x3) - y1) % P

  return (x3, y3)


def scalar_mult(k, point):
  result = None

  addend = point

  while k:
    if k & 1:
      result = point_add(result, addend)

    addend = point_add(addend, addend)

    k >>= 1

  return result


def compute_verifier(word, username, salt_hex):
  inner = hashlib.sha256(username.encode() + b":" + word).digest()

  salt = bytes.fromhex(salt_hex)

  scalar = int.from_bytes(hashlib.sha256(salt + inner).digest(), "big")

  rx, _ = scalar_mult(scalar, (GX, GY))

  x_mont = (rx + CONV_TO_M) % P

  return ("%064x" % x_mont)[:56]


def module_constraints():
  return [[0, 256], [32, 32], [0, 256], [32, 32], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  username = "hashcat"

  if salt is None:
    salt = random_hex_string(32)

  verifier = compute_verifier(word, username, salt)

  return "$mikrotik$%s$%s$%s" % (username, salt, verifier)


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$mikrotik$"):
    return None

  parts = hash_in[10:].split("$")

  if len(parts) != 3:
    return None

  username, salt_hex, verifier_hex = parts

  if len(salt_hex) != 32 or len(verifier_hex) != 56:
    return None

  new_verifier = compute_verifier(word, username, salt_hex)

  if new_verifier != verifier_hex:
    return None

  return ("$mikrotik$%s$%s$%s" % (username, salt_hex, new_verifier), word)
