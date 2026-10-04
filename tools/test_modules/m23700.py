#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct
import zlib

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_bytes, utf16le

# RAR3-p (encrypted files). The key comes from a 0x40000 round SHA1 loop over the UTF-16LE password
# and salt, with RAR's quirk of hashing the buffer while an in-place SHA1 rewrites it. Every 0x4000th
# round contributes one IV byte. The AES-128-CBC blob decrypts to data whose CRC32 is stored, so
# verify decrypts, checks the CRC and re-encrypts from the file's own fields.

ITERATIONS = 0x40000

MASK = 0xffffffff


def _rotl32(x, n):
  return ((x << n) | (x >> (32 - n))) & MASK


def _mangle_block(block):
  # RAR hashes the password buffer with a SHA1 that also overwrites it, one 64 byte block at a time.
  # The rewritten block is the words W[64..79] of the SHA1 message schedule, and that schedule does
  # not depend on the hash state, so only the input bytes are needed here.

  w = [int.from_bytes(block[k * 4:k * 4 + 4], "big") for k in range(16)]

  for i in range(16, 80):
    w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

  return b"".join(w[64 + k].to_bytes(4, "little") for k in range(16))


def _sha1_update_rar29(ctx, buf, length, count):
  ctx.update(bytes(buf))

  j = count & 63

  if (j + length) <= 63:
    return

  i = 64 - j

  if (i + 63) >= length:
    return

  while (i + 63) < length:
    buf[i:i + 64] = _mangle_block(buf[i:i + 64])

    i += 64


def _derive(word, salt):
  # Both RAR3 kernels decode the UTF-8 password with hc_enc before widening it to UTF-16LE, so the
  # oracle decodes too. Widening the raw bytes made a hash hashcat could not crack for a non ASCII
  # password. Verified: the UTF-8 encoded hash cracks in the pure and the optimized kernel alike.
  buf = bytearray(utf16le(word, "utf-8") + salt)

  length = len(buf)
  count  = 0

  ctx = hashlib.sha1()
  iv  = b""

  for i in range(ITERATIONS):
    _sha1_update_rar29(ctx, buf, length, count)

    count += length

    ctx.update(struct.pack("<I", i)[0:3])

    count += 3

    if (i & 0x3fff) == 0:
      iv += ctx.copy().digest()[19:20]

  k = ctx.digest()

  # byte swap the first four 32 bit words into the AES key
  key = b"".join(k[t * 4:t * 4 + 4][::-1] for t in range(4))

  return key, iv


def _cbc_encrypt(key, iv, data):
  pad = (-len(data)) % 16

  return AES.new(key, AES.MODE_CBC, iv).encrypt(data + b"\x00" * pad)


def _cbc_decrypt(key, iv, data):
  return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def module_constraints():
  return [[0, 128], [8, 8], [0, 20], [8, 8], [-1, -1]]


def module_generate_hash(word, salt, crc32_sum=None, pack_size=None, unpack_size=None, data=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  key, iv = _derive(word, salt)

  if data is not None:
    data_encrypted = data[0:pack_size]
    data_decrypted = _cbc_decrypt(key, iv, data_encrypted)

    data_crc = data_decrypted[0:unpack_size]

    data = b"WRONG"

    if (zlib.crc32(data_crc) & MASK) == crc32_sum:
      data = data_crc
  else:
    data = random_bytes(random_number(1, 4096))

  crc32_computed = zlib.crc32(data) & MASK
  crc32_computed = int.from_bytes(crc32_computed.to_bytes(4, "big"), "little")

  data_encrypted = _cbc_encrypt(key, iv, data)

  pack_size   = len(data_encrypted)
  unpack_size = len(data)

  return "$RAR3$*1*%s*%08x*%d*%d*1*%s*30" % (salt.hex(), crc32_computed, pack_size, unpack_size, data_encrypted.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[0:9] != "$RAR3$*1*":
    return None

  # $RAR3$*1*<salt>*<crc32>*<pack_size>*<unpack_size>*1*<data>*30
  fields = hash_in.split("*")

  if len(fields) != 9:
    return None

  salt, crc32_hex, pack_size, unpack_size, one, data, thirty = fields[2:9]

  if one != "1" or thirty != "30":
    return None

  salt_bin = bytes.fromhex(salt)
  data_bin = bytes.fromhex(data)

  crc32_sum = int.from_bytes(bytes.fromhex(crc32_hex), "little")

  new_hash = module_generate_hash(word, salt_bin, crc32_sum, int(pack_size), int(unpack_size), data_bin)

  return (new_hash, word)
