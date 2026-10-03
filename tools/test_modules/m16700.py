#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

# FileVault 2. PBKDF2-HMAC-SHA256 derives a 16 byte KEK that AES key wraps a two block key (N = 2),
# the same wrap -m 16200 uses. Verify unwraps the stored blob and, when the RFC 3394 integrity
# constant comes back, wraps it again so the printed hash is rebuilt from the file's own fields.


def _wrap(cipher, a, p1, p2):
  for j in range(6):
    b  = cipher.encrypt(a + p1)
    a  = strxor(b[0:8], (2 * j + 1).to_bytes(8, "big"))
    p1 = b[8:16]

    b  = cipher.encrypt(a + p2)
    a  = strxor(b[0:8], (2 * j + 2).to_bytes(8, "big"))
    p2 = b[8:16]

  return a + p1 + p2


def _unwrap(cipher, blob):
  a  = blob[0:8]
  p1 = blob[8:16]
  p2 = blob[16:24]

  for j in range(5, -1, -1):
    b  = cipher.decrypt(strxor(a, (2 * j + 2).to_bytes(8, "big")) + p2)
    a  = b[0:8]
    p2 = b[8:16]

    b  = cipher.decrypt(strxor(a, (2 * j + 1).to_bytes(8, "big")) + p1)
    a  = b[0:8]
    p1 = b[8:16]

  return a, p1, p2


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, z_pk=None, wrapped_key=None):
  iterations = int(iterations) if iterations else 20000
  z_pk       = int(z_pk) if z_pk else 1

  salt_bin = bytes.fromhex(salt)

  kek = hashlib.pbkdf2_hmac("sha256", word, salt_bin, iterations, 16)

  cipher = AES.new(kek, AES.MODE_ECB)

  if wrapped_key is not None:
    a, p1, p2 = _unwrap(cipher, bytes.fromhex(wrapped_key))

    if a == b"\xa6" * 8:
      blob_bin = _wrap(cipher, a, p1, p2)
    else:
      blob_bin = b"\xff" * 24
  else:
    blob_bin = _wrap(cipher, b"\xa6" * 8, b"\xff" * 8, b"\xff" * 8)

  return "$fvde$%d$%d$%s$%d$%s" % (z_pk, len(salt_bin), salt_bin.hex(), iterations, blob_bin.hex())


def module_verify_hash(line):
  parts = line.split(b":")

  if len(parts) < 2:
    return None

  hash_in = parts[0].decode(errors="replace")
  word    = parts[1]

  fields = hash_in.split("$")

  if len(fields) != 7:
    return None

  if fields[1] != "fvde":
    return None

  if fields[2] != "1":
    return None

  if fields[3] != "16":
    return None

  z_pk, salt, iterations, wrapped_key = fields[2], fields[4], fields[5], fields[6]

  return (module_generate_hash(word, salt, int(iterations), z_pk, wrapped_key), word)
