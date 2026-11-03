#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import BLAKE2b

from lib.test_helpers import random_bytes, random_number

# xchain-crypto keystore, as thorchain and thorswap wallets write it. The envelope is the Ethereum
# keystore of mode 15600 and the MAC covers the same bytes, the derived key's second half followed
# by the whole ciphertext, but it is BLAKE2b at a 256 bit digest rather than keccak256.
#
# The payload is the wallet's BIP39 recovery phrase, so its length is drawn rather than fixed. Past
# 112 bytes the MAC runs to a second BLAKE2b block.


def module_constraints():
  return [[0, 256], [0, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, ciphertext=None):
  iterations = 1024 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  if ciphertext is None:
    ciphertext = random_bytes(random_number(1, 256))

  derived_key = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, 32)

  b = BLAKE2b.new(digest_bits=256)
  b.update(derived_key[16:32] + ciphertext)
  digest = b.hexdigest()

  return "$xchain$*%i*%s*%s*%s" % (iterations, salt_bytes.hex(), ciphertext.hex(), digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:9] != "$xchain$*":
    return None

  data = hash_in.split("*")

  if len(data) != 5:
    return None

  try:
    iterations = int(data[1])
    salt = bytes.fromhex(data[2])
    ciphertext = bytes.fromhex(data[3])
  except ValueError:
    return None

  return (module_generate_hash(word, salt, iterations, ciphertext), word)
