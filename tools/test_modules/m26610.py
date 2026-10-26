#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# MetaMask (short). PBKDF2-HMAC-SHA256 of the password over a 32 byte salt, then AES-GCM. The
# ciphertext is fixed at 64 bytes and carries no tag: the oracle only checks that the plaintext is
# printable ASCII, so generation encrypts a fixed 64 byte prefix of the wallet vault JSON.

FIXED_PT = ("[{\"type\":\"HD Key Tree\",\"data\":{\"mnemonic\":"
            "[112,97,121,109,101,110,116,32,117,112,115,101,116,32,109,101,116,97,108,32,99,104,"
            "97,112,116,101,114,32,114,117,110,32,97,100,109,105,116,32,109,101,97,115,117,114,"
            "101,32,114,101,109,105,110,100,32,115,117,112,112,108,121,32,104,111,112,101,32,101,"
            "110,101,109,121,32,104,101,100,103,101,104,111,103],\"numberOfAccounts\":1,"
            "\"hdPath\":\"m/44'/60'/0'/0\"}}]").encode("ascii")

CT_LEN = 64


def module_constraints():
  return [[8, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def _is_printable(pt):
  return all(0x20 <= b <= 0x7e for b in pt)


def module_generate_hash(word, salt, iv=None, ct=None):
  if iv is None:
    iv = random_hex_string(32)

  salt_bin = bytes.fromhex(salt)
  iv_bin   = bytes.fromhex(iv)

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bin, 10000, 32)

  if ct is None:
    pt = FIXED_PT
  else:
    ct_bin = bytes.fromhex(ct)

    pt = AES.new(key, AES.MODE_GCM, nonce=iv_bin).decrypt(ct_bin)

    if not _is_printable(pt):
      pt = b""

  pt = pt[:CT_LEN]

  ct_bin = AES.new(key, AES.MODE_GCM, nonce=iv_bin).encrypt(pt)

  return "$metamask-short$%s$%s$%s" % (
    base64.b64encode(salt_bin).decode("ascii"),
    base64.b64encode(iv_bin).decode("ascii"),
    base64.b64encode(ct_bin).decode("ascii"))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:16] != "$metamask-short$":
    return None

  parts = hash_in.split("$")

  if len(parts) < 5:
    return None

  salt, iv, ct = parts[2], parts[3], parts[4]

  try:
    salt_bin = base64.b64decode(salt)
    iv_bin   = base64.b64decode(iv)
    ct_bin   = base64.b64decode(ct)
  except Exception:
    return None

  if len(salt_bin) != 32 or len(iv_bin) != 16 or len(ct_bin) != 64:
    return None

  return (module_generate_hash(word, salt_bin.hex(), iv_bin.hex(), ct_bin.hex()), word)
