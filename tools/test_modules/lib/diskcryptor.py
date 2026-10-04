#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What m20011.py, m20012.py and m20013.py have in common, which is everything but the list of
# cipher cascades a volume may have been created with and the amount of key material that takes.
#
# DiskCryptor encrypts a 2048 byte header with XTS as data unit 1. The first 64 bytes of it are
# the salt, which the hash carries in clear, so the hash holds the remaining 1984. A cascade
# re-encrypts the same 2048 bytes, the salt in front again, one pass per cipher.

import hashlib

from .test_helpers import random_bytes, random_number
from .xts import Xts

ITERATIONS = 1000
SALT_LEN   = 64
HEADER_LEN = 2048
SEQUENCE   = 1

# The three flag words DiskCryptor writes, and the three module_hash_decode () accepts. They sit
# at offset 8 of the header body and are what tells a trial decryption that it found the cascade.

FLAGS = ("02000400", "02000500", "02000800")


def _keys(word, salt_raw, count):
  # The kernel decodes the UTF-8 rather than widening the bytes, and the mode has no optimized
  # kernel, so there is no second behaviour to follow and no IS_OPTIMIZED switch either. Both this
  # helper and the kernel's own decode widened before, which is why no multi byte password was ever
  # cracked under these modes.

  utf16le = word.decode("utf-8").encode("utf-16-le")

  key = hashlib.pbkdf2_hmac("sha512", utf16le, salt_raw, ITERATIONS, count * 32)

  return [key[off:off + 32] for off in range(0, len(key), 32)]


def _encrypt(cascade, keys, salt_raw, body):
  for cipher, main, tweak in cascade:
    body = Xts(cipher, keys[main], keys[tweak]).encrypt(salt_raw + body, SEQUENCE)[SALT_LEN:]

  return body


def _decrypt(cascade, keys, salt_raw, body):
  for cipher, main, tweak in reversed(cascade):
    body = Xts(cipher, keys[main], keys[tweak]).decrypt(salt_raw + body, SEQUENCE)[SALT_LEN:]

  return body


def _plausible(body):
  return body[:4] == b"DCRP" and body[8:14].hex() in [flag + "0000" for flag in FLAGS]


def generate_hash(cascades, key_count, word, salt, data):
  salt_raw = bytes.fromhex(salt)
  keys     = _keys(word, salt_raw, key_count)

  if data is None:
    cascade = cascades[random_number(0, len(cascades) - 1)]

    body = b"DCRP" + random_bytes(4) + bytes.fromhex(FLAGS[random_number(0, 2)])
    body = body + b"\x00" * (HEADER_LEN - SALT_LEN - len(body))
  else:
    # Which cascade the volume was created with is not in the hash, so it is found by decrypting
    # with each in turn and looking at what comes out.

    for cascade in cascades:
      body = _decrypt(cascade, keys, salt_raw, data[SALT_LEN:])

      if _plausible(body):
        break
    else:
      return None

  return "$diskcryptor$0*%s%s" % (salt, _encrypt(cascade, keys, salt_raw, body).hex())


def verify_hash(cascades, key_count, line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  if not hash_in.startswith(b"$diskcryptor$"):
    return None

  star = hash_in.find(b"*", 13)

  if star < 1 or hash_in[13:star] != b"0":
    return None

  data = hash_in[star + 1:]

  if len(data) != 4096:
    return None

  try:
    raw = bytes.fromhex(data.decode("ascii"))
  except (UnicodeDecodeError, ValueError):
    return None

  digest = generate_hash(cascades, key_count, word, data[:128].decode("ascii"), raw)

  if digest is None:
    return None

  return (digest, word)
