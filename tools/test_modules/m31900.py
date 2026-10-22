#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# MetaMask mobile vault. The base64 of the salt is the PBKDF2-HMAC-SHA512 salt, the key it derives
# does AES-256-CBC with no padding, and only the first 32 bytes of the ciphertext are stored. On
# verify a decrypt that is not printable ASCII is treated as a wrong password and a blank plaintext
# is re-encrypted instead.

FAKE_PT = (
  b"[{\"type\":\"HD Key Tree\",\"data\":{\"mnemonic\":\"ocean hidden kidney famous "
  b"rich season gloom husband spring convince attitude boy\",\"numberOfAccounts\":1,"
  b"\"hdPath\":\"m/44'/60'/0'/0\"}}]"
)


def module_constraints():
  return [[8, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def _is_printable(data):
  return all(0x20 <= b <= 0x7e for b in data)


def module_generate_hash(word, salt, iv=None, ct=None):
  if iv is None:
    iv = random_hex_string(32)

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  salt_b64 = base64.b64encode(salt_bytes).decode("ascii")

  key = hashlib.pbkdf2_hmac("sha512", word, salt_b64.encode("ascii"), 5000, 32)

  iv_bin = bytes.fromhex(iv)

  if ct is None:
    pt = FAKE_PT
  else:
    dec = AES.new(key, AES.MODE_CBC, iv_bin).decrypt(bytes.fromhex(ct))
    pt = dec if _is_printable(dec) else b""

  # only the first two blocks are stored, and CBC makes those depend on the first 32 plaintext bytes
  # alone, so encrypting that slice reproduces the stored ciphertext without padding the rest

  ct1 = AES.new(key, AES.MODE_CBC, iv_bin).encrypt(pt[:32])[:32]

  return "$metamaskMobile$%s$%s$%s" % (salt_b64, iv, base64.b64encode(ct1).decode("ascii"))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:16] != "$metamaskMobile$":
    return None

  data = hash_in.split("$")

  if len(data) != 5:
    return None

  _, _signature, salt_field, iv_field, ct_field = data

  try:
    salt_bytes = base64.b64decode(salt_field)
    iv_bin     = bytes.fromhex(iv_field)
    ct_bin     = base64.b64decode(ct_field)
  except (ValueError, base64.binascii.Error):
    return None

  if len(salt_bytes) != 16 or len(iv_bin) != 16 or len(ct_bin) != 32:
    return None

  return (module_generate_hash(word, salt_bytes, iv_field, ct_bin.hex()), word)
