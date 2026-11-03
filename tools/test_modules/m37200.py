#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_hex_string, random_number

# The scrypt parameters default to gocryptfs's own, N=65536 r=8 p=1, and they have to stay equal to
# the ones in the module's self-test hash: hashcat refuses to run when the loaded hash asks for a
# different scrypt configuration than the self-test vector was built with.
#
# gocryptfs: scrypt(word, salt) gives a key that AES-256-GCM unwraps the 32 byte master key with,
# and the password is right when the GCM tag verifies. With the HKDF feature flag, which every
# volume since gocryptfs 1.3 sets, that scrypt output goes through HKDF-SHA256 first and the nonce
# is 16 bytes rather than 12. The associated data is the 8 byte block number, zero for the master
# key. When a stored ciphertext and tag are present the tag is checked; a mismatch or a fresh
# generate wraps random bytes instead, so the emitted line is self consistent either way.

HKDF_INFO = b"AES-GCM file content encryption"


def _hkdf_sha256(ikm, info, length):
  prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()

  okm = b""
  t = b""
  i = 1

  while len(okm) < length:
    t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
    okm += t
    i += 1

  return okm[:length]


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, hkdf=None, scrypt_n=65536, scrypt_r=8, scrypt_p=1, iv=None, data=None, tag=None):
  if hkdf is None:
    hkdf = random_number(0, 1)

  if iv is None:
    iv = random_hex_string(32 if hkdf == 1 else 24)

  salt_bin = bytes.fromhex(salt)

  maxmem = 128 * scrypt_n * scrypt_r * (scrypt_p + 2)

  key_bin = hashlib.scrypt(word, salt=salt_bin, n=scrypt_n, r=scrypt_r, p=scrypt_p, dklen=32, maxmem=maxmem)

  if hkdf == 1:
    key_bin = _hkdf_sha256(key_bin, HKDF_INFO, 32)

  iv_bin = bytes.fromhex(iv)

  aad = b"\x00" * 8

  pt = None

  if data is not None:
    data_bin = bytes.fromhex(data)
    tag_bin = bytes.fromhex(tag)

    aes = AES.new(key_bin, AES.MODE_GCM, nonce=iv_bin, mac_len=16)
    aes.update(aad)
    pt = aes.decrypt(data_bin)

    try:
      aes.verify(tag_bin)
    except ValueError:
      pt = random_bytes(32)
  else:
    pt = random_bytes(32)

  aes = AES.new(key_bin, AES.MODE_GCM, nonce=iv_bin, mac_len=16)
  aes.update(aad)
  ct_bin, tag_bin = aes.encrypt_and_digest(pt)

  return "$gocryptfs$2*%u*%u*%u*%u*%s*%s" % (
    hkdf, scrypt_n, scrypt_r, scrypt_p, salt_bin.hex(), (iv_bin + ct_bin + tag_bin).hex())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[:11] != "$gocryptfs$":
    return None

  fields = hash_in[11:].split("*")

  if len(fields) != 7:
    return None

  version, hkdf, scrypt_n, scrypt_r, scrypt_p, salt, blob = fields

  if version != "2":
    return None

  if (hkdf != "0") and (hkdf != "1"):
    return None

  iv_len = 16 if hkdf == "1" else 12

  blob_bin = bytes.fromhex(blob)

  if len(blob_bin) != (iv_len + 32 + 16):
    return None

  iv = blob_bin[:iv_len]
  data = blob_bin[iv_len:iv_len + 32]
  tag = blob_bin[iv_len + 32:]

  new_hash = module_generate_hash(word, salt, None, int(hkdf), int(scrypt_n), int(scrypt_r),
                                  int(scrypt_p), iv.hex(), data.hex(), tag.hex())

  return (new_hash, word)
