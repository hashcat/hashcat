#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import zlib

from lib.pkzip import ZipCrypto
from lib.test_helpers import random_bytes, random_number


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  method = 8 if random_number(0, 1) else 0
  content = random_bytes(random_number(1 if method == 8 else 4, 128))

  if method == 8:
    if random_number(0, 1):
      content = b'A' * 32768

    strategy = zlib.Z_FIXED if random_number(0, 1) else zlib.Z_DEFAULT_STRATEGY
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15, strategy=strategy)
    data = compressor.compress(content) + compressor.flush()
  else:
    data = content

  crc = zlib.crc32(content)
  header = random_bytes(11) + bytes([crc >> 24])
  payload = ZipCrypto(word).encrypt(header + data)

  if len(payload) > 256:
    return None

  return '$pkzip-stream$*%d*0*%x*%x*%08x*%02x*%s*-' % (
    method, len(payload), len(content), crc, crc >> 24, payload.hex())


def module_verify_hash(line):
  try:
    value, word = line.split(b':', 1)
    parts = value.decode('ascii').split('*')

    if len(parts) != 9 or parts[0] != '$pkzip-stream$':
      return None

    method = int(parts[1], 16)
    offset, packed, unpacked, crc, check = (int(v, 16) for v in parts[2:7])
    sample = bytes.fromhex(parts[7])

    if parts[8] != '-' or offset != 0 or unpacked == 0:
      return None

    if method not in (0, 8) or (method == 0 and unpacked < 4):
      return None

    payload = sample

    if len(payload) != packed or not payload.startswith(sample):
      return None

    plain = ZipCrypto(word).decrypt(payload)

    if len(plain) < 12 or plain[11] != check:
      return None

    content = zlib.decompress(plain[12:], -15) if method == 8 else plain[12:]

    if len(content) != unpacked or zlib.crc32(content) != crc:
      return None

    return value.decode('ascii'), word
  except (ValueError, OSError, zlib.error):
    return None
