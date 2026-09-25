#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import random
import zlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib.test_helpers import random_hex_string, random_string

# Electrum wallet v4. The key is the sha512 of the ECDH shared point between a PBKDF2 derived private
# scalar and the stored ephemeral public key on secp256k1. It splits into an AES-128-CBC iv and key
# for the deflated wallet JSON and an HMAC-SHA256 key over the ciphertext.

MAX_DATA_LEN = 16384

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _point_add(pt1, pt2):
  if pt1 is None:
    return pt2

  if pt2 is None:
    return pt1

  x1, y1 = pt1
  x2, y2 = pt2

  if x1 == x2 and (y1 + y2) % P == 0:
    return None

  if pt1 == pt2:
    m = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
  else:
    m = (y2 - y1) * pow(x2 - x1, P - 2, P) % P

  x3 = (m * m - x1 - x2) % P
  y3 = (m * (x1 - x3) - y1) % P

  return (x3, y3)


def _point_mul(k, pt):
  result = None

  while k > 0:
    if k & 1:
      result = _point_add(result, pt)

    pt = _point_add(pt, pt)
    k >>= 1

  return result


def _decompress_point(prefix, x):
  # secp256k1 oct2point on a compressed point, or None when x has no square root or is out of field

  if x >= P:
    return None

  rhs = (pow(x, 3, P) + 7) % P

  y = pow(rhs, (P + 1) // 4, P)

  if (y * y - rhs) % P != 0:
    return None

  if (y & 1) != (prefix - 2):
    y = P - y

  return (x, y)


def generate_key(word, ephemeral_pubkey):
  private_key = hashlib.pbkdf2_hmac("sha512", word, b"", 1024, 64)

  m = int.from_bytes(private_key, "big")

  q = _decompress_point(ephemeral_pubkey[0], int.from_bytes(ephemeral_pubkey[1:], "big"))

  if q is None:
    return None

  rx, ry = _point_mul(m, q)

  public_key = bytes([0x02 if (ry & 1) == 0 else 0x03]) + rx.to_bytes(32, "big")

  return hashlib.sha512(public_key).digest()


def module_generate_hash(word, salt=None, iterations=None):
  key = None
  ephemeral_pubkey = b""

  while key is None:
    sign_of_curve_point = random.randrange(2)

    ephemeral_pubkey = bytes.fromhex("0%d%s" % (sign_of_curve_point + 2, random_hex_string(64)))

    key = generate_key(word, ephemeral_pubkey)

  compressed_data = b""

  while True:
    data_buf = "{\r\n    \""

    if random.randrange(2) == 1:
      data_buf = "{\n    \""

    # a 30 percent compression rate is assumed, so the plaintext is oversized to land the ciphertext
    # in the tokenizer's window

    data_length = 64 + random.randrange(int(MAX_DATA_LEN * 1.30 + 1))

    random_length = data_length - len(data_buf)

    if random_length > 0:
      data_buf += random_string(random_length)

    deflator = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, zlib.MAX_WBITS, 9)

    compressed_data = deflator.compress(data_buf.encode("latin-1")) + deflator.flush()

    if len(compressed_data) < 64:
      continue

    if (len(compressed_data) + 15) > MAX_DATA_LEN:
      continue

    break

  iv = key[0:16]
  aes_key = key[16:32]

  encrypted_data = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(compressed_data, 16))

  hmac_key = key[32:64]

  mac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).hexdigest()

  return "$electrum$4*%s*%s*%s" % (ephemeral_pubkey.hex(), encrypted_data.hex(), mac)


def module_verify_hash(line):
  index1 = line.find(b":")

  if index1 < 1:
    return None

  hash_in = line[:index1]
  word = line[index1 + 1:]

  if hash_in[:10] != b"$electrum$":
    return None

  index2 = hash_in.find(b"*")

  if index2 < 1:
    return None

  if hash_in[10:index2] != b"4":
    return None

  index1 = hash_in.find(b"*", index2 + 1)

  if index1 < 1:
    return None

  index3 = hash_in.find(b"*", index1 + 1)

  if index3 < 1:
    return None

  try:
    ephemeral_pubkey = bytes.fromhex(hash_in[index2 + 1:index1].decode("ascii"))
    data_buf = bytes.fromhex(hash_in[index1 + 1:index3].decode("ascii"))
  except (ValueError, UnicodeDecodeError):
    return None

  mac = hash_in[index3 + 1:].decode("ascii", "replace")

  key = generate_key(word, ephemeral_pubkey)

  if key is None:
    return None

  hmac_key = key[32:64]

  mac_gen = hmac.new(hmac_key, data_buf, hashlib.sha256).hexdigest()

  new_hash = hash_in.decode("ascii") if mac_gen == mac else ""

  return (new_hash, word)
