#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# APFS / FileVault (fvde). PBKDF2-HMAC-SHA256 derives a 256 bit KEK, which AES key wraps (RFC 3394)
# the 40 byte volume key blob. Verify unwraps the stored blob and, when the IV constant 0xa6..a6
# comes back, wraps it again, so the printed hash is rebuilt from the file's own fields.


def _xor8(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def _wrap(aes, a, p):
  # RFC 3394 wrap over four 8 byte blocks
  for j in range(0, 6):
    for n in range(1, 5):
      b = aes.encrypt(a + p[n - 1])
      a = _xor8(b[0:8], (4 * j + n).to_bytes(8, "big"))
      p[n - 1] = b[8:16]

  return a + b"".join(p)


def _unwrap(aes, a, p):
  for j in range(5, -1, -1):
    for n in range(4, 0, -1):
      b = _xor8(a, (4 * j + n).to_bytes(8, "big")) + p[n - 1]
      b = aes.decrypt(b)
      a = b[0:8]
      p[n - 1] = b[8:16]

  return a, p


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, z_pk=None, blob=None):
  iters = 20000 if iterations is None else int(iterations)
  z_pk = 2 if z_pk is None else int(z_pk)

  if len(salt) == 0:
    salt = random_hex_string(32)

  salt_bin = bytes.fromhex(salt)

  kek = hashlib.pbkdf2_hmac("sha256", word, salt_bin, iters, 32)

  aes = AES.new(kek, AES.MODE_ECB)

  if blob is not None:
    blob_bin = bytes.fromhex(blob)

    a = blob_bin[0:8]
    p = [blob_bin[8:16], blob_bin[16:24], blob_bin[24:32], blob_bin[32:40]]

    a, p = _unwrap(aes, a, p)

    if a == b"\xa6" * 8:
      blob_bin = _wrap(aes, a, p)
    else:
      blob_bin = b"\xff" * 40
  else:
    a = b"\xa6" * 8
    p = [b"\xff" * 8, b"\xff" * 8, b"\xff" * 8, b"\xff" * 8]

    blob_bin = _wrap(aes, a, p)

  return "$fvde$%d$%d$%s$%d$%s" % (z_pk, len(salt_bin), salt_bin.hex(), iters, blob_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  digest = line[:idx].decode(errors="replace")
  word   = line[idx + 1:]

  data = digest.split("$")

  if len(data) != 7:
    return None

  if data[1] != "fvde":
    return None

  z_pk = data[2]

  if z_pk != "2":
    return None

  if data[3] != "16":
    return None

  salt, iters, blob = data[4], data[5], data[6]

  return (module_generate_hash(word, salt, int(iters), int(z_pk), blob), word)
