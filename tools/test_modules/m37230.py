#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# A Copay backup is an sjcl blob, so the key is PBKDF2-HMAC-SHA256 of the password over the salt and
# the payload is AES-CCM. CCM encrypts with the counter blocks L - 1 | nonce | counter, where sjcl
# picks L = 2 for a backup of any realistic size, which makes the nonce the first 13 bytes of the
# iv. The payload starts at counter 1, counter 0 being the block the tag is masked with.
#
# Only the first ciphertext block takes part, because the password is verified against the prefix
# the backup JSON opens with rather than against the CCM tag.

ITER = 10000

CCM_L = 2

PREFIX = b'{"network":"live'


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def _ctr_block(iv, counter):
  return bytes([CCM_L - 1]) + iv[:15 - CCM_L] + counter.to_bytes(CCM_L, "big")


def module_generate_hash(word, salt, iterations=None, iv=None, key_size=None):
  salt_bin = bytes.fromhex(salt)

  if iterations is None:
    iterations = ITER

  if key_size is None:
    key_size = 128 if random_number(0, 1) == 0 else 256

  if iv is None:
    iv_bin = random_bytes(16)
  else:
    iv_bin = bytes.fromhex(iv)

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bin, iterations, key_size // 8)

  keystream = AES.new(key, AES.MODE_ECB).encrypt(_ctr_block(iv_bin, 1))

  ct = bytes(a ^ b for a, b in zip(PREFIX, keystream))

  return "$copay$1*%u*%u*%s*%s*%s" % (iterations, key_size, salt_bin.hex(), iv_bin.hex(), ct.hex())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:7] != "$copay$":
    return None

  fields = hash_in[7:].split("*")

  if len(fields) != 6:
    return None

  version, iterations, key_size, salt, iv, ct = fields

  if version != "1":
    return None

  if len(ct) != 32:
    return None

  return (module_generate_hash(word, salt, int(iterations), iv, int(key_size)), word)
