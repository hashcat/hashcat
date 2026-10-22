#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import Blowfish

from lib.test_helpers import random_bytes, split_hash_word

# KWallet 4, the old scheme with no salt and no PBKDF2. The key comes from password2hash and the
# 64 byte header is Blowfish ECB. KDE byte swaps every 32 bit word of the file before it reaches
# Blowfish, a bug the on disk format is stuck with.


def kwallet_alter_endianity(data):
  return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


def kwallet_password2hash(password):
  # The password is cut into 16 byte chunks, each hashed 2000 times, and the chunk digests are
  # glued into a 20, 40 or 56 byte key. The fourth chunk takes everything that is left.

  plength = len(password)

  out = b""

  oindex = 0
  i      = 0

  while True:
    if i != 0 and i >= plength:
      break

    left = plength - i

    n = left if (oindex >= 60 or left < 16) else 16

    buf = hashlib.sha1(password[i:i + n]).digest()

    for _ in range(1, 2000):
      buf = hashlib.sha1(buf).digest()

    out += buf

    if oindex >= 60:
      break

    oindex += 20
    i      += 16

  if plength <= 16:
    return out[0:20]

  if plength <= 32:
    return out[0:40]

  if plength <= 48:
    return out[0:56]

  return out[0:14] + out[20:34] + out[40:54] + out[60:74]


def kwallet_random_plain(ct_len):
  payload = bytearray(random_bytes(52))

  for i in range(0, 52, 3):
    payload[i] = 0

  head = random_bytes(8)

  size = (ct_len - 12).to_bytes(4, "big")[::-1]

  return (head + size + bytes(payload)).hex()


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, plain=None, ct_len=88):
  ct_len = int(ct_len)

  if plain is None:
    plain = kwallet_random_plain(ct_len)

  plain = bytes.fromhex(plain)

  key = kwallet_password2hash(word)

  ct_sw = plain[0:8] + Blowfish.new(key, Blowfish.MODE_ECB).encrypt(plain[8:8 + 56])

  ct = kwallet_alter_endianity(ct_sw)

  return "$kwallet$%d$%s" % (ct_len, ct.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 4:
    return None

  _, signature, ct_len, ct = data

  if signature != "kwallet" or len(ct) != 128:
    return None

  key = kwallet_password2hash(word)

  ct_sw = kwallet_alter_endianity(bytes.fromhex(ct))

  plain = ct_sw[0:8] + Blowfish.new(key, Blowfish.MODE_ECB).decrypt(ct_sw[8:8 + 56])

  new_hash = module_generate_hash(word, "", plain.hex(), int(ct_len))

  return (new_hash, word)
