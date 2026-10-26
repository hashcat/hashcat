#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

# PDF 1.7 Level 8 (Acrobat 10 and 11). The key comes from a hash chain whose digest length is
# chosen each round by the AES-CBC ciphertext of the repeated password and block: the sum of the
# first 16 cipher bytes mod 3 selects SHA-256, SHA-384 or SHA-512. The loop runs at least 64 rounds
# and keeps going while the last cipher byte plus 32 exceeds the round count.

DEFAULT_REST_TAIL = "*127*" + "0" * 254 + "*32*" + "0" * 64 + "*32*" + "0" * 64


def module_constraints():
  return [[1, 127], [32, 32], [1, 15], [32, 32], [-1, -1]]


def module_generate_hash(word, id=None, rest=None):
  if id is None:
    id = "0" * 32

  if rest is None:
    rest = "127*" + "0" * 64 + id + "0" * 158 + DEFAULT_REST_TAIL

  datax = rest.split("*")

  u = bytes.fromhex(datax[1])

  block = hashlib.sha256(word + u[32:40]).digest()

  data_len = 1
  data63   = 0

  i = 0

  while i < 64 or i < data63 + 32:
    plain = (word + block) * 64

    data_len = len(word) + len(block)

    cipher = AES.new(block[0:16], AES.MODE_CBC, block[16:32]).encrypt(plain)

    total = sum(cipher[j] for j in range(16))

    block_size = 32 + (total % 3) * 16

    if block_size == 32:
      block = hashlib.sha256(cipher[0:data_len * 64]).digest()
    elif block_size == 48:
      block = hashlib.sha384(cipher[0:data_len * 64]).digest()
    elif block_size == 64:
      block = hashlib.sha512(cipher[0:data_len * 64]).digest()

    data63 = cipher[data_len * 64 - 1]

    i += 1

  datax[1] = (block[0:32] + u[32:]).hex()

  rest = "*".join(datax)

  return "$pdf$5*6*256*-1028*1*16*%s*%s" % (id, rest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  data = hash_in.split("*")

  if len(data) < 11:
    return None

  header = ["$pdf$5", "6", "256", "-1028", "1", "16"]

  if data[0:6] != header:
    return None

  id   = data[6]
  rest = "*".join(data[7:])

  new_hash = module_generate_hash(word, id, rest)

  return (new_hash, word)
