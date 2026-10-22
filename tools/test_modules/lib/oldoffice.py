#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Old MS Office (RC4) for modes 9700 to 9820. A key of 16 bytes encrypts a chosen verifier and the
# hash of its first block; the two ciphertexts are the hash. enc1 and enc2 share one keystream (the
# second RC4 () call continues where the first left off), while the verifier is encrypted under a
# separate RC4 instance, which is what lets a known ciphertext round trip.

import hashlib

from Crypto.Cipher import ARC4


def encrypt_blocks(rc4_key, param_hex, second):
  # second is the digest used for the second block (md5 or sha1). Returns (enc1 hex, enc2 hex).

  if param_hex:
    encdata = ARC4.new(rc4_key).encrypt(bytes.fromhex(param_hex))
  else:
    encdata = b"A" * 16

  data1 = encdata
  data2 = second(data1[:16]).digest()

  c = ARC4.new(rc4_key)

  return c.encrypt(data1).hex(), c.encrypt(data2).hex()


def secblock_v3(key2, param3):
  # The optional second block for version 3. param3 is its hex; it is kept only when it decrypts to
  # at least 10 NUL bytes in the first 32, which is what marks a real block rather than a fake one.

  if not param3:
    return ""

  decrypted = ARC4.new(key2).encrypt(bytes.fromhex(param3))

  nul = sum(1 for i in range(32) if i < len(decrypted) and decrypted[i] == 0)

  return "*" + param3 if nul >= 10 else "*"


def random_secblock_v3(key2):
  # A real second block: 10 to 32 NUL bytes with a few random bytes inserted, encrypted. Drawn
  # through lib/test_helpers so a seeded run is reproducible.

  from lib.test_helpers import random_bytes, random_number

  num_zeros = random_number(10, 32)

  block = bytearray(b"\x00" * num_zeros)

  for _ in range(32 - num_zeros):
    idx = random_number(0, num_zeros + len(block) - num_zeros)
    block[idx:idx] = random_bytes(1)

  return "*" + ARC4.new(key2).encrypt(bytes(block)).hex()
