#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# Android FDE from 4.4 on, the footers whose kdf_type is KDF_SCRYPT. The stored string is
#
#   $androidfde$2$<N>$<r>$<p>$<salt>$<encrypted master key>$<1536 bytes of the encrypted disk>
#
# and the chain is
#
#   scrypt(password, salt, N, r, p, 32) -> key(16) || iv(16)
#   master key = AES-128-CBC-decrypt(encrypted master key, key, iv)
#
# The 2 is the footer's own kdf_type, so a KDF_SCRYPT_KEYMASTER footer is told apart by its 5
# rather than by guesswork. N, r and p come out of the footer as base 2 logarithms, so the
# defaults below are what SCRYPT_DEFAULTS of { 15, 3, 1 } actually means.
#
# A KitKat footer carries no scrypted_intermediate_key, so nothing in it checks a password. As in
# mode 8800 the kernel decides by decrypting part of the disk and recognizing a filesystem, and
# this oracle builds the ext case.
#
# The superblock lives 1024 bytes into the image, and the kernel reads three fields out of it:
# s_first_data_block < 2, s_log_block_size < 16 and s_magic == 0xEF53. It gets them by
# AES-CBC-decrypting bytes 1040 to 1087 using the 16 bytes ahead of them as the IV, which is a
# known flaw in the implementation (the real IV would be the ESSIV of that sector, so the first 16
# bytes of the sector never decrypt correctly and the kernel simply does not look at them).
# Encrypting the same way is what makes the fields land where the kernel expects.

KDF_SCRYPT = 2

SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 2

DATA_LEN = 1536

SB_OFF = 1024  # where the superblock starts, and with it the IV of its own tail
SB_IV  = 16
SB_LEN = 48

EXT_MAGIC = 0xEF53


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


def _ikey(word, salt_raw, n, r, p):
  return hashlib.scrypt(word, salt=salt_raw, n=n, r=r, p=p, dklen=32,
                        maxmem=(128 * n * r * (p + 2)))


def _build(n, r, p, salt, encrypted, data):
  return "$androidfde$%d$%d$%d$%d$%s$%s$%s" % (KDF_SCRYPT, n, r, p, salt,
                                               encrypted.hex(), data.hex())


def module_generate_hash(word, salt, iterations=None, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
  salt_raw = bytes.fromhex(salt)

  ikey = _ikey(word, salt_raw, n, r, p)

  master_key = random_bytes(16)

  encrypted = AES.new(ikey[:16], AES.MODE_CBC, iv=ikey[16:]).encrypt(master_key)

  sb = bytearray(random_bytes(SB_LEN))

  struct.pack_into("<I", sb,  4, random_number(0, 1))   # s_first_data_block, must be < 2
  struct.pack_into("<I", sb,  8, random_number(0, 15))  # s_log_block_size,   must be < 16
  struct.pack_into("<H", sb, 40, EXT_MAGIC)

  sb_iv = random_bytes(SB_IV)

  data = bytearray(random_bytes(DATA_LEN))

  data[SB_OFF:SB_OFF + SB_IV] = sb_iv
  data[SB_OFF + SB_IV:SB_OFF + SB_IV + SB_LEN] = \
    AES.new(master_key, AES.MODE_CBC, iv=sb_iv).encrypt(bytes(sb))

  return _build(n, r, p, salt, encrypted, bytes(data))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  parts = hash_in.split(b"$")

  if len(parts) != 9 or parts[1] != b"androidfde":
    return None

  try:
    kdf_type  = int(parts[2])
    n         = int(parts[3])
    r         = int(parts[4])
    p         = int(parts[5])
    salt      = parts[6].decode("ascii")
    encrypted = bytes.fromhex(parts[7].decode("ascii"))
    data      = bytes.fromhex(parts[8].decode("ascii"))
  except (UnicodeDecodeError, ValueError):
    return None

  if kdf_type != KDF_SCRYPT:
    return None

  if len(salt) != 32 or len(encrypted) != 16 or len(data) != DATA_LEN:
    return None

  if n < 2 or (n & (n - 1)) != 0 or r < 1 or p < 1:
    return None

  ikey = _ikey(word, bytes.fromhex(salt), n, r, p)

  master_key = AES.new(ikey[:16], AES.MODE_CBC, iv=ikey[16:]).decrypt(encrypted)

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

  return (_build(n, r, p, salt, encrypted, data), word)
