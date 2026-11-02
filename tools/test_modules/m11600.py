#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct
import zlib

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib.test_helpers import random_number, random_string, kernel_charset

# 7-Zip. The AES-256 key is one SHA-256 over 2^num_cycle_power copies of the UTF-16LE password each
# followed by an 8 byte little endian counter. The (zero padded) salt is the CBC IV. Generate
# encrypts a random buffer with Crypt::CBC standard (PKCS7) padding and stores its CRC32; verify
# decrypts, truncates to unpack_size and recomputes the CRC.


def module_constraints():
  return [[0, 256], [0, 16], [0, 20], [0, 16], [-1, -1]]


def _derive_key(word, num_cycle_power):
  word_utf16le = word.decode(kernel_charset(), errors="replace").encode("utf-16-le")

  rounds = 1 << num_cycle_power

  ctx = hashlib.sha256()

  for i in range(rounds):
    ctx.update(word_utf16le + struct.pack("<Q", i))

  return ctx.digest()


def module_generate_hash(word, salt, iterations=None, seven_zip_salt_len=None,
                         seven_zip_salt_buf=None, salt_len=None, data_len=None,
                         unpack_size=None, data_buf=None):
  p = 0

  validation_only = seven_zip_salt_len is not None

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if validation_only:
    num_cycle_power    = int(iterations)
    seven_zip_salt_len = int(seven_zip_salt_len)
    salt_len           = int(salt_len)
    data_len           = int(data_len)
    unpack_size        = int(unpack_size)
  else:
    num_cycle_power    = 14
    seven_zip_salt_len = 0
    seven_zip_salt_buf = ""
    salt_len           = len(salt)
    unpack_size        = random_number(1, 32 + 1)
    data_buf           = random_string(unpack_size).encode("latin-1")

  key = _derive_key(word, num_cycle_power)

  salt_buf = salt

  if len(salt_buf) < 16:
    salt_buf = salt_buf + b"\x00" * (16 - len(salt_buf))

  if validation_only:
    decrypted_data = AES.new(key, AES.MODE_CBC, salt_buf).decrypt(data_buf)
    decrypted_data = decrypted_data[0:unpack_size]

    hash_buf = zlib.crc32(decrypted_data) & 0xffffffff
  else:
    hash_buf = zlib.crc32(data_buf) & 0xffffffff

    data_buf = AES.new(key, AES.MODE_CBC, salt_buf).encrypt(pad(data_buf, 16))
    data_len = len(data_buf)

  return "$7z$%d$%d$%d$%s$%d$%s$%d$%d$%d$%s" % (
    p, num_cycle_power, seven_zip_salt_len, seven_zip_salt_buf, salt_len,
    salt_buf.hex(), hash_buf, data_len, unpack_size, data_buf.hex())


def module_verify_hash(line):
  if line[0:4] != b"$7z$":
    return None

  hash_in = line.split(b":", 1)

  if len(hash_in) != 2:
    return None

  fields = hash_in[0].decode(errors="replace").split("$")

  # ['', '7z', p, num_cycle_power, sz_salt_len, sz_salt_buf, salt_len, salt, crc, data_len, unpack_size, data]
  if len(fields) != 12 or fields[1] != "7z" or fields[2] != "0":
    return None

  word = hash_in[1]

  iterations         = fields[3]
  seven_zip_salt_len = fields[4]
  seven_zip_salt_buf = fields[5]
  salt_len           = fields[6]
  salt               = bytes.fromhex(fields[7])
  data_len           = fields[9]
  unpack_size        = fields[10]
  data_buf           = bytes.fromhex(fields[11])

  new_hash = module_generate_hash(word, salt, iterations, seven_zip_salt_len,
                                  seven_zip_salt_buf, salt_len, data_len,
                                  unpack_size, data_buf)

  return (new_hash, word)
