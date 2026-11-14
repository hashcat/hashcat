#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import os
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_number

# Brave Wallet vault: key = PBKDF2-HMAC-SHA256(password, salt32, iter, 32),
# blob = AES-256-GCM-SIV(key, nonce12).Seal(pt) = ct || tag (RFC 8452).
# Hash line: $brave$*<iterations>*<salt_hex>*<nonce_hex>*<ct+tag_hex>
#
# pycryptodome has no GCM-SIV, so the AEAD is inline pure python (verified
# against the RFC 8452 Appendix C.2 vectors).

ROUNDS = 1000

X_INV = (1 << 127) | (1 << 124) | (1 << 121) | (1 << 114) | 1


def _polyval_mul(x, y):
  z = 0
  v = y
  for i in range(128):
    if (x >> i) & 1:
      z ^= v
    carry = v >> 127
    v = (v << 1) & ((1 << 128) - 1)
    if carry:
      v ^= (1 << 127) | (1 << 126) | (1 << 121) | 1
  return z


def _polyval(h, msg):
  s = 0
  hint = int.from_bytes(h, "little")
  for off in range(0, len(msg), 16):
    blk = int.from_bytes(msg[off:off + 16], "little")
    s = _polyval_mul(_polyval_mul(s ^ blk, hint), X_INV)
  return s.to_bytes(16, "little")


def _pad16(b):
  return b if len(b) % 16 == 0 else b + b"\x00" * (16 - len(b) % 16)


def _gcm_siv_keymat(key, nonce):
  ek = AES.new(key, AES.MODE_ECB)

  keymat = b""
  for i in range(6):
    keymat += ek.encrypt(struct.pack("<I", i) + nonce)[:8]

  return keymat


def _gcm_siv_tag(key, nonce, pt, aad=b""):
  keymat = _gcm_siv_keymat(key, nonce)

  auth_key, enc_key = keymat[:16], keymat[16:48]

  s_s = _polyval(auth_key,
                 _pad16(aad) + _pad16(pt) +
                 struct.pack("<Q", len(aad) * 8) + struct.pack("<Q", len(pt) * 8))
  s_s = bytearray(s_s)
  for i in range(12):
    s_s[i] ^= nonce[i]
  s_s[15] &= 0x7f

  ek2 = AES.new(enc_key, AES.MODE_ECB)
  return ek2.encrypt(bytes(s_s))


def _gcm_siv_seal(key, nonce, pt, aad=b""):
  keymat = _gcm_siv_keymat(key, nonce)

  enc_key = keymat[16:48]

  tag = _gcm_siv_tag(key, nonce, pt, aad)

  ctr = bytearray(tag)
  ctr[15] |= 0x80
  ct = bytearray()
  ek2 = AES.new(enc_key, AES.MODE_ECB)
  for off in range(0, len(pt), 16):
    ks = ek2.encrypt(bytes(ctr))
    blk = pt[off:off + 16]
    ct += bytes(a ^ b for a, b in zip(blk, ks))
    c = (int.from_bytes(ctr[0:4], "little") + 1) & 0xffffffff
    ctr[0:4] = c.to_bytes(4, "little")

  return bytes(ct) + tag


def _gcm_siv_open(key, nonce, ct, tag, aad=b""):
  keymat = _gcm_siv_keymat(key, nonce)

  enc_key = keymat[16:48]

  ctr = bytearray(tag)
  ctr[15] |= 0x80
  pt = bytearray()
  ek2 = AES.new(enc_key, AES.MODE_ECB)
  for off in range(0, len(ct), 16):
    ks = ek2.encrypt(bytes(ctr))
    blk = ct[off:off + 16]
    pt += bytes(a ^ b for a, b in zip(blk, ks))
    c = (int.from_bytes(ctr[0:4], "little") + 1) & 0xffffffff
    ctr[0:4] = c.to_bytes(4, "little")

  return _gcm_siv_tag(key, nonce, bytes(pt), aad) == tag


def _make_hash(word, salt):
  if isinstance(word, str):
    word = word.encode()

  nonce = os.urandom(12)

  key = hashlib.pbkdf2_hmac("sha256", word, salt, ROUNDS, 32)

  pt = os.urandom(random_number(1, 128))

  blob = _gcm_siv_seal(key, nonce, pt)

  return "$brave$*%d*%s*%s*%s" % (ROUNDS, salt.hex(), nonce.hex(), blob.hex())


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None):
  if salt is None:
    salt = os.urandom(32)

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if len(salt) < 32:
    salt = salt + os.urandom(32 - len(salt))
  elif len(salt) > 32:
    salt = salt[:32]

  return _make_hash(word, salt)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$brave$*"):
    return None

  fields = hash_in.split("*")

  if len(fields) != 5:
    return None

  try:
    iter_ = int(fields[1])
    salt  = bytes.fromhex(fields[2])
    nonce = bytes.fromhex(fields[3])
    blob  = bytes.fromhex(fields[4])
  except Exception:
    return None

  ct, tag = blob[:-16], blob[-16:]

  key = hashlib.pbkdf2_hmac("sha256", word, salt, iter_, 32)

  if not _gcm_siv_open(key, nonce, ct, tag):
    return None

  return (hash_in, word)
