#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import struct

from Crypto.Cipher import AES

from test_helpers import random_bytes, random_number

# Android FDE <= 4.3. The stored string is
#
#   $fde$16$<salt>$16$<encrypted master key>$<1536 bytes of the encrypted disk>
#
# and the chain is
#
#   PBKDF2-HMAC-SHA1(password, salt, 2000, 32) -> key(16) || iv(16)
#   master key = AES-128-CBC-decrypt(encrypted master key, key, iv)
#
# There is no checksum on the master key. The kernel decides a password is right by decrypting
# part of the disk with it and recognizing a filesystem, either a FAT boot sector or an ext
# superblock. This oracle builds the ext case, which is the cheaper of the two to construct.
#
# The superblock lives 1024 bytes into the image, and the kernel reads three fields out of it:
# s_first_data_block < 2, s_log_block_size < 16 and s_magic == 0xEF53. It gets them by
# AES-CBC-decrypting bytes 1040 to 1087 using the 16 bytes ahead of them as the IV, which is a
# known flaw in the implementation (the real IV would be the ESSIV of that sector, so the first 16
# bytes of the sector never decrypt correctly and the kernel simply does not look at them).
# Encrypting the same way is what makes the fields land where the kernel expects.

ITERATIONS = 2000
DATA_LEN   = 1536

SB_OFF = 1024  # where the superblock starts, and with it the IV of its own tail
SB_IV  = 16
SB_LEN = 48

EXT_MAGIC = 0xEF53


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def _master_key(word, salt_raw, encrypted):
  dk = hashlib.pbkdf2_hmac("sha1", word, salt_raw, ITERATIONS, 32)

  return AES.new(dk[:16], AES.MODE_CBC, iv=dk[16:]).decrypt(encrypted)


def _build(salt, encrypted, data):
  return "$fde$16$%s$16$%s$%s" % (salt, encrypted.hex(), data.hex())


def module_generate_hash(word, salt, iterations=None):
  salt_raw = bytes.fromhex(salt)

  dk = hashlib.pbkdf2_hmac("sha1", word, salt_raw, ITERATIONS, 32)

  master_key = random_bytes(16)

  encrypted = AES.new(dk[:16], AES.MODE_CBC, iv=dk[16:]).encrypt(master_key)

  sb = bytearray(random_bytes(SB_LEN))

  struct.pack_into("<I", sb,  4, random_number(0, 1))   # s_first_data_block, must be < 2
  struct.pack_into("<I", sb,  8, random_number(0, 15))  # s_log_block_size,   must be < 16
  struct.pack_into("<H", sb, 40, EXT_MAGIC)

  sb_iv = random_bytes(SB_IV)

  data = bytearray(random_bytes(DATA_LEN))

  data[SB_OFF:SB_OFF + SB_IV]          = sb_iv
  data[SB_OFF + SB_IV:SB_OFF + SB_IV + SB_LEN] = \
    AES.new(master_key, AES.MODE_CBC, iv=sb_iv).encrypt(bytes(sb))

  return _build(salt, encrypted, bytes(data))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"$")

  if len(parts) != 7 or parts[1] != b"fde":
    return None

  try:
    salt      = parts[3].decode("ascii")
    encrypted = bytes.fromhex(parts[5].decode("ascii"))
    data      = bytes.fromhex(parts[6].decode("ascii"))
  except (UnicodeDecodeError, ValueError):
    return None

  if len(salt) != 32 or len(encrypted) != 16 or len(data) != DATA_LEN:
    return None

  master_key = _master_key(word, bytes.fromhex(salt), encrypted)

  sb_iv = data[SB_OFF:SB_OFF + SB_IV]
  sb_ct = data[SB_OFF + SB_IV:SB_OFF + SB_IV + SB_LEN]

  sb = AES.new(master_key, AES.MODE_CBC, iv=sb_iv).decrypt(sb_ct)

  # the three fields the kernel reads, which is what says the master key came out right

  if struct.unpack_from("<I", sb, 4)[0] >= 2:
    return None

  if struct.unpack_from("<I", sb, 8)[0] >= 16:
    return None

  if struct.unpack_from("<H", sb, 40)[0] != EXT_MAGIC:
    return None

  return (_build(salt, encrypted, data), word)
