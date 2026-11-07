#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# A BitGo key is an sjcl blob of the xprv of a BIP32 master key, so the key is PBKDF2-HMAC-SHA256 of
# the password over the salt and the payload is AES-CCM. CCM encrypts with the counter blocks
# L - 1 | nonce | counter, where sjcl picks L = 2 for a payload of this size, which makes the nonce
# the first 13 bytes of the iv. The payload starts at counter 1, counter 0 being the block the tag
# is masked with.
#
# Only the first ciphertext block takes part, because the password is verified against the 16
# characters every master xprv opens with, on mainnet or on testnet, rather than against the tag.

ITER = 10000

CCM_L = 2

PREFIXES = (b"xprv9s21ZrQH143K", b"tprv8ZgxMBicQKsP")


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def _ctr_block(iv, counter):
  return bytes([CCM_L - 1]) + iv[:15 - CCM_L] + counter.to_bytes(CCM_L, "big")


def module_generate_hash(word, salt, iterations=None, iv=None, key_size=None, prefix=None):
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

  if prefix is None:
    prefix = PREFIXES[random_number(0, 1)]

  keystream = AES.new(key, AES.MODE_ECB).encrypt(_ctr_block(iv_bin, 1))

  ct = bytes(a ^ b for a, b in zip(prefix, keystream))

  line = "$bitgo$1*%u*%u*%s*%s*%s" % (iterations, key_size, salt_bin.hex(), iv_bin.hex(), ct.hex())

  return line


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:7] != "$bitgo$":
    return None

  fields = hash_in[7:].split("*")

  if len(fields) != 6:
    return None

  version, iterations, key_size, salt, iv, ct = fields

  if version != "1":
    return None

  if len(ct) != 32:
    return None

  # the line does not say which network the key is for, so the one that reproduces it is the answer

  for prefix in PREFIXES:
    line_out = module_generate_hash(word, salt, int(iterations), iv, int(key_size), prefix)

    if line_out == hash_in:
      return (line_out, word)

  line_out = module_generate_hash(word, salt, int(iterations), iv, int(key_size), PREFIXES[0])

  return (line_out, word)
