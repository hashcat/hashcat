#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_bytes

# Apple iWork. PBKDF2-HMAC-SHA1 makes a 16 byte AES-128 key, and the blob is AES-CBC with no padding.
# The plaintext is 32 bytes of data followed by its SHA-256, so verify decrypts, checks that pair and
# re-encrypts from the file's own fields.

FORMAT = 1


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, hash_ver=None, file_ver=None, iterations=None, iv=None, data=None):
  is_decrypt = data is not None

  if not is_decrypt:
    kind = random_number(1, 2)

    if kind == 1:
      hash_ver = 1
      file_ver = 2
      iterations = 100000
      salt = salt[:32]
    else:
      hash_ver = 2
      file_ver = 1
      iterations = 4000
      salt = salt[:16]

    salt = bytes.fromhex(salt)

    iv   = random_bytes(16)
    data = random_bytes(32)
    data += hashlib.sha256(data).digest()

  iters = int(iterations)

  key = hashlib.pbkdf2_hmac("sha1", word, salt, iters, 16)

  if is_decrypt:
    decrypted = AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    raw_data = decrypted[0:32]
    checksum = decrypted[32:64]

    data = b"WRONG"

    if hashlib.sha256(raw_data).digest() == checksum:
      data = decrypted

  encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(data)

  return "$iwork$%d$%d$%d$%d$%s$%s$%s" % (int(hash_ver), int(file_ver), FORMAT, iters, salt.hex(), iv.hex(), encrypted.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[0:7] != "$iwork$":
    return None

  data = hash_in.split("$")

  # leading empty field, then signature, so nine fields total
  if len(data) != 9:
    return None

  hash_ver, file_ver, fmt, iters, salt, iv, blob = data[2:9]

  if hash_ver not in ("1", "2") or file_ver not in ("1", "2"):
    return None

  if fmt != "1":
    return None

  return (module_generate_hash(word, bytes.fromhex(salt), hash_ver, file_ver, int(iters), bytes.fromhex(iv), bytes.fromhex(blob)), word)
