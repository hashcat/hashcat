#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Util.Padding import pad, unpad

from lib.test_helpers import random_bytes

# Ethereum pre-sale wallet. PBKDF2-HMAC-SHA256 of the password (its own salt) makes an AES-128 key
# that CBC encrypts the seed; the keccak-256 of the seed with a trailing 0x02 is the stored check.


def module_constraints():
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, ethaddr, iterations=None, encseed=None):
  key = hashlib.pbkdf2_hmac("sha256", word, word, 2000, 16)

  if encseed is not None:
    iv = encseed[:16]
    body = encseed[16:]
    seed = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(body), 16)
  else:
    iv = random_bytes(16)
    seed = random_bytes(592)
    body = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(seed, 16))
    encseed = iv + body

  digest = keccak.new(digest_bits=256).update(seed + b"\x02").hexdigest()

  return "$ethereum$w*%s*%s*%s" % (encseed.hex(), ethaddr, digest[:32])


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:12] != "$ethereum$w*":
    return None

  data = hash_in.split("*")

  if len(data) != 4:
    return None

  encseed = bytes.fromhex(data[1])
  ethaddr = data[2]

  return (module_generate_hash(word, ethaddr, encseed=encseed), word)
