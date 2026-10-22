#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import RIPEMD160
from Crypto.Util.strxor import strxor

from lib import whirlpool
from lib.pyserpent import Serpent
from lib.pytwofish import Twofish
from lib.test_helpers import random_bytes, random_number

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
# Every one of the fifteen combinations is its own kernel, from m14511 for SHA-1 with AES to
# m14553 for Whirlpool with Twofish, and the type field is what selects it. The type is an
# argument with a fixed default, the way m24600 handles the same thing: hashcat builds one kernel
# per run, so a file that mixed types could only ever crack the hashes that happened to match the
# kernel it built. A caller that wants one of the other fourteen asks for it, and the key size is
# free to vary inside one file because the kernel reads it rather than being picked by it.

DIGESTS = (
  lambda b: hashlib.sha1(b).digest(),
  lambda b: hashlib.sha256(b).digest(),
  lambda b: hashlib.sha512(b).digest(),
  lambda b: RIPEMD160.new(b).digest(),
  lambda b: whirlpool.whirlpool(b),
)

CIPHERS = (
  lambda key, block: AES.new(key, AES.MODE_ECB).encrypt(block),
  lambda key, block: Serpent(key).encrypt(block),
  lambda key, block: Twofish(key).encrypt(block),
)

KEY_LEN = (16, 24, 32)

TYPE_DEFAULT = 0


def module_constraints():
  return [[0, 64], [-1, -1], [0, 31], [-1, -1], [-1, -1]]


def _key(word, hash_type, key_size):
  digest = DIGESTS[hash_type // 3]

  key = digest(word)

  if len(key) < KEY_LEN[key_size]:
    key += digest(b"A" + word)

  return key[:KEY_LEN[key_size]]


def _build(hash_type, key_size, iv, plain, cipher):
  return "$cryptoapi$%d$%d$%s$%s$%s" % (hash_type, key_size, iv.hex(), plain.hex(), cipher.hex())


def module_generate_hash(word, salt, iterations=None, hash_type=None, key_size=None, iv=None, plain=None):
  hash_type = TYPE_DEFAULT if hash_type is None else int(hash_type)
  key_size  = random_number(0, 2) if key_size is None else int(key_size)

  if iv is None:
    iv = random_bytes(16)

  if plain is None:
    plain = random_bytes(16)

  cipher = CIPHERS[hash_type % 3](_key(word, hash_type, key_size), strxor(plain, iv))

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

  if hash_type < 0 or hash_type > 14 or key_size > 2:
    return None

  if len(iv) != 16 or len(plain) != 16:
    return None

  return (module_generate_hash(word, None, None, hash_type, key_size, iv, plain), word)
