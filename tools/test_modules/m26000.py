#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import DES

from lib.test_helpers import random_hex_string

# Mozilla key3.db (3DES). A chain of sha1 and HMAC-SHA1 over the two salts derives a 3DES key and IV
# that CBC encrypt the fixed check string. EDE3 is spelled out with single DES so a derived key that
# looks like a degenerate 3DES key still runs, as Crypt::DES_EDE3 allows.

CHECK = b"password-check\x02\x02"


def _hmac_sha1(data, key):
  return hmac.new(key, data, hashlib.sha1).digest()


def _ede3_encrypt(key, block):
  return DES.new(key[16:24], DES.MODE_ECB).encrypt(
    DES.new(key[8:16], DES.MODE_ECB).decrypt(
      DES.new(key[0:8], DES.MODE_ECB).encrypt(block)))


def _ede3_decrypt(key, block):
  return DES.new(key[0:8], DES.MODE_ECB).decrypt(
    DES.new(key[8:16], DES.MODE_ECB).encrypt(
      DES.new(key[16:24], DES.MODE_ECB).decrypt(block)))


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def module_constraints():
  return [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, global_salt, entry_salt=None, ct=None):
  entry_salt = random_hex_string(40) if entry_salt is None else entry_salt

  global_salt_bin = bytes.fromhex(global_salt)
  entry_salt_bin = bytes.fromhex(entry_salt)

  hp = hashlib.sha1(global_salt_bin + word).digest()

  pes = (entry_salt_bin + b"\x00" * 20)[:20]

  chp = hashlib.sha1(hp + entry_salt_bin).digest()

  k1 = _hmac_sha1(pes + entry_salt_bin, chp)
  tk = _hmac_sha1(pes, chp)
  k2 = _hmac_sha1(tk + entry_salt_bin, chp)

  k = k1 + k2

  key = k[0:24]
  iv = k[32:40]

  if ct is not None:
    ct_bin = bytes.fromhex(ct)

    ct1, ct2 = ct_bin[0:8], ct_bin[8:16]

    pt1 = _xor(_ede3_decrypt(key, ct1), iv)
    pt2 = _xor(_ede3_decrypt(key, ct2), ct1)

    pt = pt1 + pt2

    if pt != CHECK:
      pt = b"\xff" * 16
  else:
    pt = CHECK

  ct1 = _ede3_encrypt(key, _xor(pt[0:8], iv))
  ct2 = _ede3_encrypt(key, _xor(pt[8:16], ct1))

  ct_bin = ct1 + ct2

  return "$mozilla$*3DES*%s*%s*%s" % (global_salt_bin.hex(), entry_salt_bin.hex(), ct_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:9] != "$mozilla$":
    return None

  data = hash_in.split("*")

  if len(data) != 5 or data[1] != "3DES":
    return None

  _, _, global_salt, entry_salt, ct = data

  return (module_generate_hash(word, global_salt, entry_salt, ct), word)
