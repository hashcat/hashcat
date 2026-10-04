#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# AxCrypt 2 AES-256. PBKDF2-HMAC-SHA512 gives a 64 byte key that is folded to 32 bytes and xored
# with the wrap salt, then an AxCrypt variant of RFC 3394 key wrap (idx xored into bytes 4:8 after
# each encrypt) protects the 144 byte blob. Verify unwraps and checks for the 0xa6 magic at offset 0.

AXCRYPT_MAGIC = bytes.fromhex("a6a6a6a6a6a6a6a6")

BLOCKS = 6


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt_wrap, iter_wrap=None, data=None, salt_kdf=None, iter_kdf=None):
  # the runner hands iterations through as None, so the perl "shift // default" is reproduced here
  iter_wrap = 10000 if iter_wrap is None else int(iter_wrap)
  iter_kdf = 1000 if iter_kdf is None else int(iter_kdf)

  if isinstance(salt_wrap, str):
    salt_wrap = salt_wrap.encode("latin-1")

  if salt_kdf is None:
    salt_kdf = random_bytes(32)

  kdf = hashlib.pbkdf2_hmac("sha512", word, salt_kdf, iter_kdf, 64)

  # fold the 64 byte key down to the 32 byte AES key
  kek = _xor(kdf[0:32], kdf[32:64])
  kek = _xor(kek, salt_wrap[0:32])

  aes = AES.new(kek, AES.MODE_ECB)

  if data is not None:
    d = bytearray(data)

    for j in range(iter_wrap - 1, -1, -1):
      for k in range(BLOCKS, 0, -1):
        idx = BLOCKS * j + k

        block = d[0:4] + _xor(d[4:8], idx.to_bytes(4, "big")) + d[k * 8:k * 8 + 8]
        block = aes.decrypt(bytes(block))

        d[0:8] = block[0:8]
        d[k * 8:k * 8 + 8] = block[8:16]

    if bytes(d).find(AXCRYPT_MAGIC) != 0:
      data = b"WRONG"
  else:
    data = bytearray(AXCRYPT_MAGIC + random_bytes(136))

    for j in range(0, iter_wrap):
      for k in range(1, BLOCKS + 1):
        idx = BLOCKS * j + k

        block = bytearray(aes.encrypt(bytes(data[0:8] + data[k * 8:k * 8 + 8])))
        block[4:8] = _xor(block[4:8], idx.to_bytes(4, "big"))

        data[0:8] = block[0:8]
        data[k * 8:k * 8 + 8] = block[8:16]

    data = bytes(data)

  return "$axcrypt$*2*%i*%s*%s*%i*%s" % (iter_wrap, salt_wrap.hex(), data.hex(), iter_kdf, salt_kdf.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith("$axcrypt$*2"):
    return None

  fields = hash_in.split("*")

  if len(fields) != 7:
    return None

  iter_wrap, salt_wrap, data, iter_kdf, salt_kdf = fields[2:7]

  if not re.match(r"^[0-9]{1,7}$", iter_wrap) or not re.match(r"^[0-9]{1,7}$", iter_kdf):
    return None

  if not re.match(r"^[0-9a-fA-F]+$", salt_wrap) or not re.match(r"^[0-9a-fA-F]+$", data) or not re.match(r"^[0-9a-fA-F]+$", salt_kdf):
    return None

  try:
    salt_wrap = bytes.fromhex(salt_wrap)
    data = bytes.fromhex(data)
    salt_kdf = bytes.fromhex(salt_kdf)
  except ValueError:
    return None

  return (module_generate_hash(word, salt_wrap, iter_wrap, data, salt_kdf, iter_kdf), word)
