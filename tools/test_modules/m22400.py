#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import random_bytes, split_hash_word

# AES Crypt (SHA256): 8192 rounds of SHA-256 over the key and the password widened to UTF-16LE byte
# by byte, starting from the salt and 16 zero bytes, then HMAC-SHA256 of the IV and the file key.


def module_constraints():
  return [[0, 128], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, iv=None, key_aes=None):
  if iv is None:
    iv = random_bytes(16)

  if key_aes is None:
    key_aes = random_bytes(32)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  wide = word.decode("latin-1").encode("utf-16-le")

  key = salt_bytes + b"\x00" * 16

  for _ in range(8192):
    key = hashlib.sha256(key + wide).digest()

  digest = hmac.new(key, iv + key_aes, hashlib.sha256).hexdigest()

  return "$aescrypt$1*%s*%s*%s*%s" % (salt_bytes.hex(), iv.hex(), key_aes.hex(), digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 5 or data[0] != "$aescrypt$1" or len(data[1]) != 32 or len(data[2]) != 32 or len(data[3]) != 64:
    return None

  try:
    salt, iv, key_aes = (bytes.fromhex(d) for d in data[1:4])
  except ValueError:
    return None

  return (module_generate_hash(word, salt, None, iv, key_aes), word)
