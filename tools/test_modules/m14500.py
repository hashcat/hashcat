#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import RIPEMD160
from Crypto.Util.strxor import strxor

from test_helpers import random_bytes, random_number

# Linux Kernel Crypto API (2.4). This is a known plaintext attack, not a hash:
#
#   $cryptoapi$<type>$<key size>$<IV>$<plaintext>$<ciphertext>
#
# where type picks one of five digests crossed with one of three ciphers, key size is 0, 1 or 2
# for 128, 192 or 256 bits, and the three trailing fields are 16 bytes each. A password is right
# when encrypting plaintext XOR IV under the key derived from it reproduces the ciphertext, which
# is one CBC block.
#
# The key is dm-crypt's "plain" derivation: the digest of the password, cut to the key size. A
# digest too short to fill the key, which is SHA-1 and RIPEMD-160 at 20 bytes each, is topped up
# from a second digest, of the password with a literal "A" in front of it. That is what the
# kernels spell out as ctx.w0[0] = 0x41000000 with ctx.len = 1.
#
# This oracle covers the AES types, 0, 3, 6 and 9, across all three key sizes, which is every key
# derivation path the mode has: the two short digests that need the second pass and the two long
# ones that do not. Serpent, Twofish and Whirlpool are left out, as they were in the .pm this
# replaces, and test.sh covers those ciphers through the containers in tools/cl_tests.

DIGESTS = {
  0: lambda b: hashlib.sha1(b).digest(),
  3: lambda b: hashlib.sha256(b).digest(),
  6: lambda b: hashlib.sha512(b).digest(),
  9: lambda b: RIPEMD160.new(b).digest(),
}

KEY_LEN = (16, 24, 32)


def module_constraints():
  return [[0, 64], [-1, -1], [0, 31], [-1, -1], [-1, -1]]


def _key(word, hash_type, key_size):
  digest = DIGESTS[hash_type]

  key = digest(word)

  if len(key) < KEY_LEN[key_size]:
    key += digest(b"A" + word)

  return key[:KEY_LEN[key_size]]


def _build(hash_type, key_size, iv, plain, cipher):
  return "$cryptoapi$%d$%d$%s$%s$%s" % (hash_type, key_size, iv.hex(), plain.hex(), cipher.hex())


def module_generate_hash(word, salt, iterations=None):
  types     = sorted(DIGESTS)
  hash_type = types[random_number(0, len(types) - 1)]
  key_size  = random_number(0, 2)

  iv    = random_bytes(16)
  plain = random_bytes(16)

  cipher = AES.new(_key(word, hash_type, key_size), AES.MODE_ECB).encrypt(strxor(plain, iv))

  return _build(hash_type, key_size, iv, plain, cipher)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"$")

  if len(parts) != 7 or parts[1] != b"cryptoapi":
    return None

  try:
    hash_type = int(parts[2])
    key_size  = int(parts[3])
    iv        = bytes.fromhex(parts[4].decode("ascii"))
    plain     = bytes.fromhex(parts[5].decode("ascii"))
  except (UnicodeDecodeError, ValueError):
    return None

  if hash_type not in DIGESTS or key_size > 2:
    return None

  if len(iv) != 16 or len(plain) != 16:
    return None

  cipher = AES.new(_key(word, hash_type, key_size), AES.MODE_ECB).encrypt(strxor(plain, iv))

  return (_build(hash_type, key_size, iv, plain, cipher), word)
