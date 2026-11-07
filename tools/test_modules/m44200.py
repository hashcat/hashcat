#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import json

from Crypto.Cipher import Salsa20

from lib.test_helpers import random_bytes, random_number, split_hash_word

# sollet.io keeps the wallet's mnemonic in a NaCl secretbox under PBKDF2-HMAC-SHA256 of the password,
# 32 bytes. A secretbox is XSalsa20: HSalsa20 makes a subkey from the key and the first 16 bytes of
# the nonce, and Salsa20 under that subkey and the last 8 bytes of the nonce gives the keystream.
# Its first 32 bytes are the Poly1305 key and the rest encrypts the message. The box is the 16 byte
# tag followed by the ciphertext.
#
# The message is JSON.stringify ({ mnemonic, seed, derivationPath }), so it always opens with
# {"mnemonic":" and a BIP39 word of at least 3 lowercase letters. The line carries the first 16
# bytes of the ciphertext, and a password is verified against those rather than against the tag.

SIGNATURE = "$sollet$"

ITER = 100000

PREFIX = b'{"mnemonic":"'

WORDS = ("abandon", "ability", "able", "about", "above", "absent", "zone", "zoo", "cat", "wrist")

MASK = 0xffffffff

SIGMA = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def _rotl(v, c):
  return ((v << c) & MASK) | (v >> (32 - c))


def _salsa20_rounds(x):
  x = list(x)

  for _ in range(10):
    x[ 4] ^= _rotl((x[ 0] + x[12]) & MASK,  7)
    x[ 8] ^= _rotl((x[ 4] + x[ 0]) & MASK,  9)
    x[12] ^= _rotl((x[ 8] + x[ 4]) & MASK, 13)
    x[ 0] ^= _rotl((x[12] + x[ 8]) & MASK, 18)
    x[ 9] ^= _rotl((x[ 5] + x[ 1]) & MASK,  7)
    x[13] ^= _rotl((x[ 9] + x[ 5]) & MASK,  9)
    x[ 1] ^= _rotl((x[13] + x[ 9]) & MASK, 13)
    x[ 5] ^= _rotl((x[ 1] + x[13]) & MASK, 18)
    x[14] ^= _rotl((x[10] + x[ 6]) & MASK,  7)
    x[ 2] ^= _rotl((x[14] + x[10]) & MASK,  9)
    x[ 6] ^= _rotl((x[ 2] + x[14]) & MASK, 13)
    x[10] ^= _rotl((x[ 6] + x[ 2]) & MASK, 18)
    x[ 3] ^= _rotl((x[15] + x[11]) & MASK,  7)
    x[ 7] ^= _rotl((x[ 3] + x[15]) & MASK,  9)
    x[11] ^= _rotl((x[ 7] + x[ 3]) & MASK, 13)
    x[15] ^= _rotl((x[11] + x[ 7]) & MASK, 18)

    x[ 1] ^= _rotl((x[ 0] + x[ 3]) & MASK,  7)
    x[ 2] ^= _rotl((x[ 1] + x[ 0]) & MASK,  9)
    x[ 3] ^= _rotl((x[ 2] + x[ 1]) & MASK, 13)
    x[ 0] ^= _rotl((x[ 3] + x[ 2]) & MASK, 18)
    x[ 6] ^= _rotl((x[ 5] + x[ 4]) & MASK,  7)
    x[ 7] ^= _rotl((x[ 6] + x[ 5]) & MASK,  9)
    x[ 4] ^= _rotl((x[ 7] + x[ 6]) & MASK, 13)
    x[ 5] ^= _rotl((x[ 4] + x[ 7]) & MASK, 18)
    x[11] ^= _rotl((x[10] + x[ 9]) & MASK,  7)
    x[ 8] ^= _rotl((x[11] + x[10]) & MASK,  9)
    x[ 9] ^= _rotl((x[ 8] + x[11]) & MASK, 13)
    x[10] ^= _rotl((x[ 9] + x[ 8]) & MASK, 18)
    x[12] ^= _rotl((x[15] + x[14]) & MASK,  7)
    x[13] ^= _rotl((x[12] + x[15]) & MASK,  9)
    x[14] ^= _rotl((x[13] + x[12]) & MASK, 13)
    x[15] ^= _rotl((x[14] + x[13]) & MASK, 18)

  return x


def _words(data):
  return [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]


def hsalsa20(key, nonce16):
  k = _words(key)
  n = _words(nonce16)

  x = [SIGMA[0], k[0], k[1], k[2], k[3], SIGMA[1], n[0], n[1], n[2], n[3], SIGMA[2], k[4], k[5], k[6], k[7], SIGMA[3]]

  z = _salsa20_rounds(x)

  subkey = b"".join(z[i].to_bytes(4, "little") for i in (0, 5, 10, 15, 6, 7, 8, 9))

  return subkey


def poly1305(key, msg):
  r = int.from_bytes(key[0:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
  s = int.from_bytes(key[16:32], "little")

  p = (1 << 130) - 5

  acc = 0

  for i in range(0, len(msg), 16):
    block = msg[i:i + 16] + b"\x01"

    acc = ((acc + int.from_bytes(block, "little")) * r) % p

  tag = ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")

  return tag


def secretbox(msg, nonce, key):
  subkey = hsalsa20(key, nonce[0:16])

  stream = Salsa20.new(key=subkey, nonce=nonce[16:24]).encrypt(bytes(32 + len(msg)))

  ct = bytes(a ^ b for a, b in zip(msg, stream[32:]))

  box = poly1305(stream[0:32], ct) + ct

  return box


def secretbox_head(box_ct16, nonce, key):
  subkey = hsalsa20(key, nonce[0:16])

  stream = Salsa20.new(key=subkey, nonce=nonce[16:24]).encrypt(bytes(32 + len(box_ct16)))

  pt = bytes(a ^ b for a, b in zip(box_ct16, stream[32:]))

  return pt


def is_valid_head(pt):
  if pt[0:13] != PREFIX:
    return False

  for c in pt[13:16]:
    if (c < 0x61) or (c > 0x7a):
      return False

  return True


def make_plaintext():
  mnemonic = " ".join(WORDS[random_number(0, len(WORDS) - 1)] for _ in range(24))

  seed = random_bytes(64).hex()

  plaintext = json.dumps({"mnemonic": mnemonic, "seed": seed, "derivationPath": "bip44Change"}, separators=(",", ":"))

  return plaintext.encode()


def module_generate_hash(word, salt, iterations=None, nonce=None, plaintext=None):
  salt_bin = bytes.fromhex(salt)

  if iterations is None:
    iterations = ITER

  if nonce is None:
    nonce_bin = random_bytes(24)
  else:
    nonce_bin = bytes.fromhex(nonce)

  if plaintext is None:
    plaintext = make_plaintext()

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bin, iterations, 32)

  box = secretbox(plaintext, nonce_bin, key)

  line = "%s%u*%s*%s*%s" % (SIGNATURE, iterations, salt_bin.hex(), nonce_bin.hex(), box[16:32].hex())

  return line


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if hash_in[:len(SIGNATURE)] != SIGNATURE:
    return None

  fields = hash_in[len(SIGNATURE):].split("*")

  if len(fields) != 4:
    return None

  iterations, salt, nonce, ct = fields

  if len(ct) != 32:
    return None

  key = hashlib.pbkdf2_hmac("sha256", word, bytes.fromhex(salt), int(iterations), 32)

  # the line carries only the head of the box, so it is reproduced when the password opens it, and
  # a line with another head stands for a password that does not

  if is_valid_head(secretbox_head(bytes.fromhex(ct), bytes.fromhex(nonce), key)) == True:
    return (hash_in, word)

  line_out = module_generate_hash(word, salt, int(iterations), nonce, PREFIX + b"zzz")

  return (line_out, word)
