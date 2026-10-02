#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string, random_number

# iPhone passcode (UID key + logical KEK). PBKDF2-HMAC-SHA1 of the passcode is run through an
# iterated AES-ECB under the device UID key, and the result is the AES key-wrap key for the class
# key. A class key that unwraps to the backup magic 0xa6a6a6a6a6a6a6a6 confirms the passcode.

MASK64 = 0xffffffffffffffff
UIDO_BACKUP_KEY = 0xa6a6a6a6a6a6a6a6


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def uido_aes_wrap(key, a, r_list):
  m = AES.new(key, AES.MODE_ECB)

  k = len(r_list)
  r = list(r_list)

  for j in range(6):
    for i in range(1, k + 1):
      idx = i - 1

      t = m.encrypt(struct.pack(">QQ", a, r[idx]))

      a = (int.from_bytes(t[0:8], "big") ^ (k * j + i)) & MASK64
      r[idx] = int.from_bytes(t[8:16], "big")

  return struct.pack(">Q", a) + b"".join(struct.pack(">Q", x) for x in r)


def uido_aes_unwrap(key, wpky):
  m = AES.new(key, AES.MODE_ECB)

  b = [int.from_bytes(wpky[i * 8:i * 8 + 8], "big") for i in range(len(wpky) // 8)]

  k = len(b) - 1
  r = b[1:]

  a = b[0]

  for j in range(5, -1, -1):
    for i in range(k, 0, -1):
      idx = i - 1

      t = m.decrypt(struct.pack(">QQ", a ^ (k * j + i), r[idx]))

      a = int.from_bytes(t[0:8], "big")
      r[idx] = int.from_bytes(t[8:16], "big")

  return a, r


def module_constraints():
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, uidkey=None, *classkeys):
  iterations = 50000 if iterations is None else int(iterations)
  uidkey = random_hex_string(32) if uidkey is None else uidkey

  classkeys = list(classkeys)

  salt_bin = bytes.fromhex(salt)
  uidkey_bin = bytes.fromhex(uidkey)

  data = hashlib.pbkdf2_hmac("sha1", word, salt_bin, 1, 32)

  data0 = data[0:16]
  data1 = data[16:32]

  iterated_key0 = data0
  iterated_key1 = data1

  m = AES.new(uidkey_bin, AES.MODE_ECB)

  iv = b"\x00" * 16

  for xorkey in range(1, iterations + 1):
    xorkey_bin = struct.pack("<4I", xorkey, xorkey, xorkey, xorkey)

    iv = m.encrypt(_xor(_xor(data0, iv), xorkey_bin))
    iterated_key0 = _xor(iterated_key0, iv)

    iv = m.encrypt(_xor(_xor(data1, iv), xorkey_bin))
    iterated_key1 = _xor(iterated_key1, iv)

  iterated_key = iterated_key0 + iterated_key1

  if classkeys:
    a, _ = uido_aes_unwrap(iterated_key, bytes.fromhex(classkeys[0]))

    if a != UIDO_BACKUP_KEY:
      classkeys[0] = "0" * 80
  else:
    r = [random_number(0, MASK64) for _ in range(4)]

    classkeys.append(uido_aes_wrap(iterated_key, UIDO_BACKUP_KEY, r).hex())

  return "$uido$%s$%s$%u$%s" % (uidkey_bin.hex(), salt_bin.hex(), iterations, "$".join(classkeys))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("$")

  data = data[1:]

  if len(data) < 4 or data[0] != "uido":
    return None

  signature, uidkey, salt, iterations = data[0], data[1], data[2], data[3]
  classkeys = data[4:]

  if len(uidkey) != 32:
    return None

  return (module_generate_hash(word, salt, int(iterations), uidkey, *classkeys), word)
