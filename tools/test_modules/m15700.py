#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Hash import keccak

from lib.test_helpers import random_bytes

# Ethereum wallet, scrypt variant. Same MAC as mode 15600, the derived key just comes from scrypt.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, scrypt_N=None, scrypt_r=8, scrypt_p=1, ciphertext=None):
  scrypt_N = 262144 if scrypt_N is None else int(scrypt_N)
  scrypt_r = int(scrypt_r)
  scrypt_p = int(scrypt_p)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  if ciphertext is None:
    ciphertext = random_bytes(32)

  derived_key = hashlib.scrypt(word, salt=salt_bytes, n=scrypt_N, r=scrypt_r, p=scrypt_p,
                               dklen=32, maxmem=(128 * scrypt_N * scrypt_r * 2))

  k = keccak.new(digest_bits=256)
  k.update(derived_key[16:32] + ciphertext)
  digest = k.hexdigest()

  return "$ethereum$s*%i*%i*%i*%s*%s*%s" % (scrypt_N, scrypt_r, scrypt_p,
                                            salt_bytes.hex(), ciphertext.hex(), digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:12] != "$ethereum$s*":
    return None

  data = hash_in.split("*")

  if len(data) != 7:
    return None

  try:
    scrypt_N = int(data[1])
    scrypt_r = int(data[2])
    scrypt_p = int(data[3])
    salt = bytes.fromhex(data[4])
    ciphertext = bytes.fromhex(data[5])
  except ValueError:
    return None

  return (module_generate_hash(word, salt, scrypt_N, scrypt_r, scrypt_p, ciphertext), word)
