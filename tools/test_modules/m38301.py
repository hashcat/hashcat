#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import random
import struct

from Crypto.Cipher import AES, DES3

from lib.test_helpers import random_bytes, test_iteration_parameters


def module_test_properties():
  # Salt is 40 hex characters (20 bytes). The runner emits this many characters.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [40, 40],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'parameters': {'iterations': 1000}},
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }


# Apple DMG (encrcdsa v2, $dmg$2), the line dmg2john writes:
#
#   $dmg$2*20*salt*32*iv*bloblen*blob*cno*datasize*chunk*1*chunk0*iterations
#
# PBKDF2-HMAC-SHA1 derives a 24 byte 3DES key. The blob is the 3DES-EDE-CBC wrap, under the first
# 8 bytes of the iv, of an AES-128 or AES-256 volume key, a 20 byte HMAC-SHA1 key, "CKIE" and a
# 0x00, padded with PKCS#7 to 48 or 64 bytes. The volume key decrypts each 4096 byte chunk with
# AES-CBC under the first 16 bytes of HMAC-SHA1 (hmac key, chunk number as a big-endian u32).
# hashcat checks only the blob, the chunks are generated so that the line is a complete one.

SIGNATURE = "$dmg$2"
KEY_LEN   = 24   # 3DES key


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def _pbkdf2(word, salt_bin, iterations):
  return hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, KEY_LEN)


def _unwrap(word, salt_bin, iterations, iv_bin, blob_bin):
  key = _pbkdf2(word, salt_bin, iterations)

  plain = DES3.new(key, DES3.MODE_CBC, iv_bin[0:8]).decrypt(blob_bin)

  if plain[-12:] != b"CKIE" + b"\x00" + b"\x07" * 7:
    return None

  return plain


def _chunk(aes_key, hmac_key, cno, plain):
  iv = hmac.new(hmac_key, struct.pack(">L", cno), hashlib.sha1).digest()[0:16]

  return AES.new(aes_key, AES.MODE_CBC, iv).encrypt(plain)


def _build(word, salt_bin, iterations):
  key = _pbkdf2(word, salt_bin, iterations)

  aes_len = random.choice([16, 32])

  aes_key  = random_bytes(aes_len)
  hmac_key = random_bytes(20)

  # 41 or 57 bytes, then 7 bytes of PKCS#7 padding to 48 or 64

  plain = aes_key + hmac_key + b"CKIE" + b"\x00" + b"\x07" * 7

  iv_bin = random_bytes(8) + b"\x00" * 24

  blob_bin = DES3.new(key, DES3.MODE_CBC, iv_bin[0:8]).encrypt(plain)

  # a chunk near the end of the image and the first chunk, both mostly zero as on a real image

  cno       = random.randint(1, 100000)
  data_size = random.choice([4608, 8192])

  chunk  = _chunk(aes_key, hmac_key, cno, b"\x00" * data_size)
  chunk0 = _chunk(aes_key, hmac_key, 0, b"\x00" * 4096)

  line = "%s*%d*%s*%d*%s*%d*%s*%d*%d*%s*1*%s*%d" % (SIGNATURE,
    len(salt_bin), salt_bin.hex(),
    len(iv_bin),   iv_bin.hex(),
    len(blob_bin), blob_bin.hex(),
    cno, data_size, chunk.hex(),
    chunk0.hex(),
    iterations)

  return line


def module_generate_hash(word, salt, iterations=None, line=None):
  iterations = ITERATION_PARAMETERS['iterations'] if iterations is None else int(iterations)

  salt_bin = bytes.fromhex(salt)

  # keep a supplied line only when its blob unwraps under this candidate, so that a wrong word
  # cannot round-trip to the input hash

  if line is None:
    return _build(word, salt_bin, iterations)

  fields = line.split("*")

  iv_bin   = bytes.fromhex(fields[4])
  blob_bin = bytes.fromhex(fields[6])

  if _unwrap(word, salt_bin, iterations, iv_bin, blob_bin) is None:
    return _build(word, salt_bin, iterations)

  return line


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in.startswith(SIGNATURE + "*") == False:
    return None

  fields = hash_in.split("*")

  if (len(fields) != 12) and (len(fields) != 13):
    return None

  salt       = fields[2]
  iterations = fields[-1]

  return (module_generate_hash(word, salt, iterations, hash_in), word)
