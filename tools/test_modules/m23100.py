#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import DES

from lib.test_helpers import random_bytes

# Apple Keychain. 3DES-EDE in outer CBC over 48 bytes, keyed by PBKDF2-HMAC-SHA1. The three DES
# stages run with a zero IV (single block ECB), the CBC chaining is done here by hand. The last
# plaintext block ends in a fixed 04 04 04 04 padding, which is what verification looks for.

ITERATIONS    = 1000
FIXED_PADDING = b"\x04\x04\x04\x04"


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def module_constraints():
  return [[0, 256], [20, 20], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iv=None, data=None):
  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bytes, ITERATIONS, 24)

  des1 = DES.new(key[0:8], DES.MODE_ECB)
  des2 = DES.new(key[8:16], DES.MODE_ECB)
  des3 = DES.new(key[16:24], DES.MODE_ECB)

  data_encrypted = b""

  if data is not None:
    iv_last = data[32:40]  # only the last block's chaining value is needed
    d = data[40:48]

    t = des3.decrypt(d)
    t = des2.encrypt(t)
    t = des1.decrypt(t)

    t = _xor(t, iv_last)

    if t[4:8] == FIXED_PADDING:
      data_encrypted = data
  else:
    iv = random_bytes(8)
    data = random_bytes(44) + FIXED_PADDING

    c = iv

    for i in range(6):
      d = _xor(data[i * 8:i * 8 + 8], c)

      t = des1.encrypt(d)
      t = des2.decrypt(t)
      t = des3.encrypt(t)

      data_encrypted += t

      c = t

  return "$keychain$*%s*%s*%s" % (salt_bytes.hex(), iv.hex(), data_encrypted.hex())


def module_verify_hash(line):
  if not line.startswith(b"$keychain$*"):
    return None

  idx1 = line.find(b"*", 11)

  if idx1 < 1:
    return None

  salt = line[11:idx1]

  if len(salt) != 40:
    return None

  idx2 = line.find(b"*", idx1 + 1)

  if idx2 < 1:
    return None

  iv = line[idx1 + 1:idx2]

  if len(iv) != 16:
    return None

  idx3 = line.find(b":", idx2 + 1)

  if idx3 < 1:
    return None

  data = line[idx2 + 1:idx3]

  if len(data) != 96:
    return None

  word = line[idx3 + 1:]

  try:
    salt = bytes.fromhex(salt.decode())
    iv   = bytes.fromhex(iv.decode())
    data = bytes.fromhex(data.decode())
  except ValueError:
    return None

  return (module_generate_hash(word, salt, iv, data), word)
