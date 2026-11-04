#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import keccak

from lib.test_helpers import random_bytes, random_number, test_iteration_parameters


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 1024}},
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }


# Ethereum wallet, PBKDF2-HMAC-SHA256 variant. The derived key's second half is keccak-256 hashed
# together with the ciphertext to form the MAC.
#
# The payload is whatever the wallet encrypted, so its length is drawn rather than fixed at the 32
# bytes of a private key. Past 120 bytes the MAC runs to a second keccak block. The salt range
# starts at zero because a Trust Wallet cloud backup carries an empty one.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, ciphertext=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  if ciphertext is None:
    ciphertext = random_bytes(random_number(1, 256))

  derived_key = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, 32)

  k = keccak.new(digest_bits=256)
  k.update(derived_key[16:32] + ciphertext)
  digest = k.hexdigest()

  return "$ethereum$p*%i*%s*%s*%s" % (iterations, salt_bytes.hex(), ciphertext.hex(), digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:12] != "$ethereum$p*":
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
