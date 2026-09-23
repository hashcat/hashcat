#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES, DES
from Crypto.Hash import MD4

from lib.test_helpers import random_bytes, random_number

# DPAPI masterkey with the PBKDF2 user-hash path (context 3). The NT hash is stretched by two PBKDF2
# HMAC-SHA256 passes over the UTF-16LE SID to make the user hash; the rest matches modes 15300/15900:
# HMAC-SHA1 with the SID derives a key, a Microsoft variant of PBKDF2 stretches it, and version 1 is
# 3DES-EDE-CBC while version 2 is AES-256-CBC. The optimized kernels widen the password byte by byte
# instead of decoding UTF-8, so the oracle picks its charset from IS_OPTIMIZED as test.sh sets it.

PW_CHARSET = "latin1"

if os.environ.get("IS_OPTIMIZED") == "0":
  PW_CHARSET = "utf-8"


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


# perl's Digest::HMAC_* take the message first and the key second, so these keep that order.

def _hmac_sha1(data, key):
  return hmac.new(key, data, hashlib.sha1).digest()


def _hmac_sha512(data, key):
  return hmac.new(key, data, hashlib.sha512).digest()


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def _des(key, block, encrypt):
  cipher = DES.new(key, DES.MODE_ECB)

  return cipher.encrypt(block) if encrypt else cipher.decrypt(block)


def get_random_dpapimk_salt(version):
  context = 3

  SID = "S-15-21-%d-%d-%d-%d" % (
    random_number(400000000, 490000000),
    random_number(400000000, 490000000),
    random_number(400000000, 490000000),
    random_number(1000, 1999))

  if version == 1:
    iterations  = random_number(4000, 24000)
    cipher_algo = "des3"
    hash_algo   = "sha1"
    cipher_len  = 208
  elif version == 2:
    iterations  = random_number(8000, 17000)
    cipher_algo = "aes256"
    hash_algo   = "sha512"
    cipher_len  = 288

  iv = random_bytes(16).hex()

  return "%d*%d*%s*%s*%s*%d*%s*%d*" % (
    version, context, SID, cipher_algo, hash_algo, iterations, iv, cipher_len)


def dpapi_pbkdf2(password, salt, iterations, keylen, prf):
  # Microsoft's variant xors every round output into the accumulator, not just the last one.

  t = b""
  k = 1

  while len(t) < keylen:
    u = ui = prf(salt + struct.pack(">I", k), password)

    for _ in range(1, iterations):
      ui = prf(u, password)
      u = _xor(u, ui)

    t += u
    k += 1

  return t[:keylen]


def module_generate_hash(word, salt_buf, dpapimk_salt=None, cipher=None):
  if dpapimk_salt is None:
    dpapimk_salt = get_random_dpapimk_salt(2)

  salt_arr = dpapimk_salt.split("*")

  version          = int(salt_arr[0])
  context          = int(salt_arr[1])
  SID              = salt_arr[2]
  cipher_algorithm = salt_arr[3]
  hash_algorithm   = salt_arr[4]
  iterations       = int(salt_arr[5])
  salt             = bytes.fromhex(salt_arr[6])
  cipher_len       = int(salt_arr[7])

  sid_enc = SID.encode("utf-16-le")

  ntlm_hash = MD4.new(word.decode(PW_CHARSET).encode("utf-16-le")).digest()

  # Crypt::PBKDF2->PBKDF2 (salt, password), so the SID is the salt and the NT hash the password.

  user_hash = hashlib.pbkdf2_hmac("sha256", ntlm_hash, sid_enc, 10000, 32)
  user_hash = hashlib.pbkdf2_hmac("sha256", user_hash, sid_enc, 1, 16)

  user_derivation_key = _hmac_sha1((SID + "\x00").encode("utf-16-le"), user_hash)

  hmac_salt = random_bytes(16)
  last_key  = random_bytes(64)

  if version == 1:
    enc_key       = _hmac_sha1(hmac_salt, user_derivation_key)
    expected_hmac = _hmac_sha1(last_key, enc_key)
    expected_hmac = expected_hmac + random_bytes(4)
  elif version == 2:
    enc_key       = _hmac_sha512(hmac_salt, user_derivation_key)
    expected_hmac = _hmac_sha512(last_key, enc_key)

  cleartext = hmac_salt + expected_hmac + last_key

  if version == 1:
    derived_key = dpapi_pbkdf2(user_derivation_key, salt, iterations, 32, _hmac_sha1)
  elif version == 2:
    derived_key = dpapi_pbkdf2(user_derivation_key, salt, iterations, 48, _hmac_sha512)

  if cipher is not None:
    cipher = bytes.fromhex(cipher)

    if version == 1:
      key = derived_key[0:24]
      iv  = derived_key[24:32]

      k1, k2, k3 = key[0:8], key[8:16], key[16:24]

      expected_cleartext = b""

      for k in range(13):
        block = cipher[k * 8:k * 8 + 8]

        out1 = _des(k3, block, False)
        out2 = _des(k2, out1, True)
        out3 = _des(k1, out2, False)

        expected_cleartext += _xor(out3[0:8], iv)

        iv = block

      last_key      = expected_cleartext[-64:]
      hmac_salt     = expected_cleartext[0:16]
      expected_hmac = expected_cleartext[16:36]

      enc_key       = _hmac_sha1(hmac_salt, user_derivation_key)
      computed_hmac = _hmac_sha1(last_key, enc_key)

      cleartext = expected_cleartext

      if expected_hmac.hex() != computed_hmac.hex():
        cleartext = b"0" * 104

    elif version == 2:
      key = derived_key[0:32]
      iv  = derived_key[32:48]

      expected_cleartext = AES.new(key, AES.MODE_CBC, iv).decrypt(cipher)

      last_key      = expected_cleartext[-64:]
      hmac_salt     = expected_cleartext[0:16]
      expected_hmac = expected_cleartext[16:80]

      enc_key       = _hmac_sha512(hmac_salt, user_derivation_key)
      computed_hmac = _hmac_sha512(last_key, enc_key)

      cleartext = expected_cleartext

      if expected_hmac.hex() != computed_hmac.hex():
        cleartext = b"0" * 144

  if version == 1:
    key = derived_key[0:24]
    iv  = derived_key[24:32]

    k1, k2, k3 = key[0:8], key[8:16], key[16:24]

    out1 = _des(k1, _xor(cleartext[0:8], iv), True)
    out2 = _des(k2, out1, False)
    out3 = _des(k3, out2, True)

    cipher = out3[0:8]

    for k in range(1, 13):
      iv = out3

      out1 = _des(k1, _xor(cleartext[k * 8:k * 8 + 8], iv), True)
      out2 = _des(k2, out1, False)
      out3 = _des(k3, out2, True)

      cipher += out3[0:8]
  else:
    key = derived_key[0:32]
    iv  = derived_key[32:48]

    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(cleartext)

  return "$DPAPImk$%d*%d*%s*%s*%s*%d*%s*%d*%s" % (
    version, context, SID, cipher_algorithm, hash_algorithm, iterations,
    salt.hex(), cipher_len, cipher.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  tmp_data = hash_in.split("$")

  if len(tmp_data) < 3 or tmp_data[1] != "DPAPImk":
    return None

  data = tmp_data[2].split("*")

  if len(data) != 9:
    return None

  version = data[0]

  if version not in ("1", "2"):
    return None

  context    = data[1]
  cipher_len = data[7]
  cipher     = data[8]

  if context != "3":
    return None

  if len(cipher) != int(cipher_len):
    return None

  if version == "1" and int(cipher_len) != 208:
    return None

  if version == "2" and int(cipher_len) != 288:
    return None

  dpapimk_salt = hash_in[len("$DPAPImk$"):]

  new_hash = module_generate_hash(word, None, dpapimk_salt, cipher)

  return (new_hash, word)
