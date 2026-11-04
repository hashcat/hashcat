#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# EncFS 1.x (.encfs6.xml), AES only. PBKDF2-HMAC-SHA1 gives the user key and a 16 byte IV. The volume
# key is stream encoded in 2 passes of AES-CFB, each pass seeded with the 32 bit checksum that leads
# the blob. The checksum is HMAC-SHA1 over the decoded volume key, folded to 32 bits.


def _ivec(key, iv, seed):
  data = iv + struct.pack("<Q", seed & 0xffffffffffffffff)

  ivec = hmac.new(key, data, hashlib.sha1).digest()[:16]

  return ivec


def _shuffle(buf):
  out = bytearray(buf)

  for i in range(1, len(out)):
    out[i] ^= out[i - 1]

  return bytes(out)


def _unshuffle(buf):
  out = bytearray(buf)

  for i in range(len(out) - 1, 0, -1):
    out[i] ^= buf[i - 1]

  return bytes(out)


def _cfb(key, ivec):
  cfb = AES.new(key, AES.MODE_CFB, ivec, segment_size=128)

  return cfb


def _mac32(key, data):
  md = hmac.new(key, data, hashlib.sha1).digest()

  h = bytearray(8)

  for i in range(19):
    h[i % 8] ^= md[i]

  value = int.from_bytes(h, "big")

  mac32 = (value >> 32) ^ (value & 0xffffffff)

  return mac32


def _stream_encode(key, iv, seed, data):
  buf = _shuffle(data)
  buf = _cfb(key, _ivec(key, iv, seed + 0)).encrypt(buf)
  buf = buf[::-1]
  buf = _shuffle(buf)
  buf = _cfb(key, _ivec(key, iv, seed + 1)).encrypt(buf)

  return buf


def _stream_decode(key, iv, seed, data):
  buf = _cfb(key, _ivec(key, iv, seed + 1)).decrypt(data)
  buf = _unshuffle(buf)
  buf = buf[::-1]
  buf = _cfb(key, _ivec(key, iv, seed + 0)).decrypt(buf)
  buf = _unshuffle(buf)

  return buf


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [20, 20],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None, key_bits=None, data=None):
  iterations = 10000 if iterations is None else int(iterations)

  key_bits = [128, 192, 256][random_number(0, 2)] if key_bits is None else int(key_bits)

  key_size = key_bits // 8

  salt_bin = salt.encode("latin-1") if isinstance(salt, str) else salt

  dk = hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, key_size + 16)

  key = dk[:key_size]
  iv  = dk[key_size:]

  # a verify run keeps the volume key the blob decodes to, so a wrong password still yields a
  # line of the same shape that cannot match

  volume_key = random_bytes(key_size + 16)

  if data is not None:
    blob = bytes.fromhex(data)

    seed = struct.unpack(">I", blob[:4])[0]

    volume_key = _stream_decode(key, iv, seed, blob[4:])

  checksum = _mac32(key, volume_key)

  blob = struct.pack(">I", checksum) + _stream_encode(key, iv, checksum, volume_key)

  return "$encfs$%u*%u*0*%u*%s*%u*%s" % (key_bits, iterations, len(salt_bin), salt_bin.hex(),
                                         len(blob), blob.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in.startswith("$encfs$") is False:
    return None

  fields = hash_in[7:].split("*")

  if len(fields) != 7:
    return None

  key_bits, iterations, cipher, salt_len, salt_hex, data_len, data_hex = fields

  if cipher != "0":
    return None

  salt_bin = bytes.fromhex(salt_hex)

  new_hash = module_generate_hash(word, salt_bin, iterations, key_bits, data_hex)

  return (new_hash, word)
