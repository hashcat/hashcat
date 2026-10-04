#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import random

# ChaCha20 in the OpenSSH "original" layout: 64 bit block counter in words 12 and 13, 64 bit iv in
# words 14 and 15, both little endian. Matches Crypt::OpenSSH::ChachaPoly ivsetup and encrypt.

PLAINTEXT = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0a2b4c6d8e"

# "expand 32-byte k" and "expand 16-byte k", picked by key size like Crypt::OpenSSH::ChachaPoly.
_CONST_256 = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
_CONST_128 = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]


def _rotl32(x, n):
  return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _quarter(x, a, b, c, d):
  x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = _rotl32(x[d] ^ x[a], 16)
  x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = _rotl32(x[b] ^ x[c], 12)
  x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = _rotl32(x[d] ^ x[a], 8)
  x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = _rotl32(x[b] ^ x[c], 7)


def _block(state):
  x = list(state)

  for _ in range(10):
    _quarter(x, 0, 4, 8, 12)
    _quarter(x, 1, 5, 9, 13)
    _quarter(x, 2, 6, 10, 14)
    _quarter(x, 3, 7, 11, 15)
    _quarter(x, 0, 5, 10, 15)
    _quarter(x, 1, 6, 11, 12)
    _quarter(x, 2, 7, 8, 13)
    _quarter(x, 3, 4, 9, 14)

  return [(x[i] + state[i]) & 0xffffffff for i in range(16)]


def _keystream(key, counter_bin, iv_bin, length):
  if len(key) == 32:
    const = _CONST_256
    key_bytes = key
  else:
    # 128 bit key, the 16 bytes are used for both halves of the key words
    const = _CONST_128
    key_bytes = key + key

  k = [int.from_bytes(key_bytes[i:i + 4], "little") for i in range(0, 32, 4)]
  iv = [int.from_bytes(iv_bin[0:4], "little"), int.from_bytes(iv_bin[4:8], "little")]

  ctr = int.from_bytes(counter_bin, "little")

  out = bytearray()

  while len(out) < length:
    state = const + k + [ctr & 0xffffffff, (ctr >> 32) & 0xffffffff, iv[0], iv[1]]

    for w in _block(state):
      out += w.to_bytes(4, "little")

    ctr += 1

  return bytes(out[:length])


def module_constraints():
  return [[32, 32], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, param=None, param2=None, param3=None):
  if len(word) not in (16, 32):
    # Crypt::OpenSSH::ChachaPoly accepts only 128 or 256 bit keys
    return None

  if param is not None:
    counter = param
    offset = int(param2)
    iv = param3
  else:
    counter = "0400000000000003"
    offset = int(random.random() * 63)
    iv = "0200000000000001"

  ks = _keystream(word, bytes.fromhex(counter), bytes.fromhex(iv), len(PLAINTEXT))

  enc = bytes(p ^ k for p, k in zip(PLAINTEXT, ks))

  enc_offset = enc[offset:offset + 8]

  return "$chacha20$*%s*%d*%s*%s*%s" % (
    counter, offset, iv, PLAINTEXT[offset:offset + 8].hex(), enc_offset.hex())


def module_verify_hash(line):
  index1 = line.find(b":")

  if index1 < 0:
    return None

  hash_in = line[:index1]
  word = line[index1 + 1:]

  if len(hash_in) < 11:
    return None

  if hash_in[:11] != b"$chacha20$*":
    return None

  data = hash_in.decode(errors="replace").split("*")

  if len(data) != 6:
    return None

  param = data[1]   # counter
  param2 = data[2]  # offset
  param3 = data[3]  # iv

  new_hash = module_generate_hash(word, None, param, param2, param3)

  return (new_hash, word)
