#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

# BIP39 passphrase recovery. The mnemonic and one of its addresses are given, and the candidate is
# the passphrase that salts the seed. The derivation path carries a brace range, so one candidate
# produces an address at every index in it and the hash matches at one of them. The address here is
# P2SH-P2WPKH, which hashes the witness script rather than the public key.

P  = 2**256 - 2**32 - 977
N  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PATH     = "m/49'/0'/0'/0/{0-7}"
INDICES  = range(0, 8)
HIT      = 3

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def point_add(p1, p2):
  if p1 is None:
    return p2

  if p2 is None:
    return p1

  x1, y1 = p1
  x2, y2 = p2

  if x1 == x2 and (y1 + y2) % P == 0:
    return None

  if x1 == x2 and y1 == y2:
    lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
  else:
    lam = (y2 - y1) * pow(x2 - x1, -1, P) % P

  x3 = (lam * lam - x1 - x2) % P
  y3 = (lam * (x1 - x3) - y1) % P

  return (x3, y3)


def scalar_mult(k):
  result = None

  addend = (GX, GY)

  while k:
    if k & 1:
      result = point_add(result, addend)

    addend = point_add(addend, addend)

    k >>= 1

  return result


def serialize_point(point):
  prefix = b"\x03" if (point[1] & 1) else b"\x02"

  return prefix + point[0].to_bytes(32, "big")


def hash160(data):
  ripemd = hashlib.new("ripemd160")
  ripemd.update(hashlib.sha256(data).digest())

  return ripemd.digest()


def base58check(payload):
  raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

  value = int.from_bytes(raw, "big")
  out   = ""

  while value:
    value, rest = divmod(value, 58)
    out = B58[rest] + out

  for byte in raw:
    if byte != 0:
      break

    out = "1" + out

  return out


def child_key(key, chain, index):
  if index >= 0x80000000:
    data = b"\x00" + key.to_bytes(32, "big")
  else:
    data = serialize_point(scalar_mult(key))

  digest = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()

  return ((int.from_bytes(digest[:32], "big") + key) % N, digest[32:])


def p2sh_address(passphrase, index):
  seed = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), b"mnemonic" + passphrase, 2048, 64)

  master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

  key   = int.from_bytes(master[:32], "big")
  chain = master[32:]

  for element in (0x80000000 + 49, 0x80000000, 0x80000000, 0, index):
    key, chain = child_key(key, chain, element)

  witness = b"\x00\x14" + hash160(serialize_point(scalar_mult(key)))

  return base58check(b"\x05" + hash160(witness))


def module_constraints():
  return [[0, 256], [-1, -1], [0, 256], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  if isinstance(word, str):
    word = word.encode()

  return "%s:%s:%s" % (MNEMONIC, p2sh_address(word, HIT), PATH)


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  parts = hash_in.split(":")

  if len(parts) != 3:
    return None

  mnemonic, address, path = parts

  if mnemonic != MNEMONIC:
    return None

  if path != PATH:
    return None

  # The hash names one address and the path names a range, so the candidate is right when any index
  # in the range reproduces it.

  for index in INDICES:
    if p2sh_address(word, index) == address:
      return ("%s:%s:%s" % (mnemonic, address, path), word)

  return None
