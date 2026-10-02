#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string, random_number

# 1Password style mobile keychain. PBKDF2-HMAC-SHA256 over the password gives a key that is XORed
# with the stored hkdf key to form the AES-GCM master unlock key. On verify the stored ct is
# decrypted and kept only when its tag checks out, so a wrong password re-encrypts a fixed
# plaintext instead and does not round trip.

FAKE_PT = (
  b"{'key_ops': ['decrypt', 'encrypt'], 'kty': 'oct', 'alg': 'A256GCM', "
  b"'k': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=', 'ext': True, "
  b"'kid': 'xxxxxxxxxxxxxxxxxxxxxxxxxx'}"
)


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, hkdf_salt, hkdf_key=None, iterations=None, iv=None,
                         ct=None, tag=None, email=None):
  if hkdf_key is None:
    hkdf_key = random_hex_string(64)

  if iterations is None:
    iterations = 100000

  if iv is None:
    # a 16 or a 12 byte nonce, drawn the way the perl oracle draws it so a seeded run agrees
    iv = random_hex_string(32) if random_number(0, 1) else random_hex_string(24)

  if email is None:
    email = "31800@hashcat.net"

  iterations = int(iterations)

  hkdf_salt_bin = bytes.fromhex(hkdf_salt)
  hkdf_key_bin  = bytes.fromhex(hkdf_key)
  iv_bin        = bytes.fromhex(iv)

  password_key = hashlib.pbkdf2_hmac("sha256", word, hkdf_salt_bin, iterations, 32)

  muk = bytes(a ^ b for a, b in zip(password_key[:32], hkdf_key_bin[:32]))

  pt = FAKE_PT

  if ct is not None:
    cipher = AES.new(muk, AES.MODE_GCM, nonce=iv_bin)
    dec = cipher.decrypt(bytes.fromhex(ct))

    try:
      cipher.verify(bytes.fromhex(tag))
      pt = dec
    except ValueError:
      pt = FAKE_PT

  cipher = AES.new(muk, AES.MODE_GCM, nonce=iv_bin)
  ct_bin, tag_bin = cipher.encrypt_and_digest(pt)

  return "$mobilekeychain$%s$%s$%s$%u$%s$%s$%s" % (
    email, hkdf_salt_bin.hex(), hkdf_key_bin.hex(), iterations,
    iv_bin.hex(), ct_bin.hex(), tag_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:16] != "$mobilekeychain$":
    return None

  data = hash_in.split("$")

  if len(data) != 9:
    return None

  _, _signature, email, hkdf_salt, hkdf_key, iterations, iv, ct, tag = data

  return (module_generate_hash(word, hkdf_salt, hkdf_key, iterations, iv, ct, tag, email), word)
