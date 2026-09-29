#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.test_helpers import random_bytes, random_number, split_hash_word

# MIFARE Ultralight C 3DES key recovery. The password is a 4 byte segment of the 16 byte 3DES key;
# the rest of the key is the salt. Reader mode ($mode 1) rebuilds a valid RndA/RndB authentication
# exchange, so the stored ERndB and the two CBC blocks pin the key segment.


def module_constraints():
  return [[4, 4], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _e(k, d):
  return DES.new(k, DES.MODE_ECB).encrypt(d)


def _d(k, d):
  return DES.new(k, DES.MODE_ECB).decrypt(d)


def _tdes_e(k16, d):
  k1, k2 = k16[:8], k16[8:16]

  return _e(k1, _d(k2, _e(k1, d)))


def _tdes_d(k16, d):
  k1, k2 = k16[:8], k16[8:16]

  return _d(k1, _e(k2, _d(k1, d)))


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def module_generate_hash(word, salt, mode=None, segment=None, lfsr=None, erndb=None, blk1=None, blk2=None, basekey=None):
  mode = 1 if mode is None else int(mode)
  segment = random_number(1, 4) if segment is None else int(segment)
  lfsr = 0 if lfsr is None else int(lfsr)

  if basekey is not None:
    base_key = bytearray(bytes.fromhex(basekey))
  else:
    base_key = bytearray(random_bytes(16))
    off = (segment - 1) * 4
    base_key[off:off + 4] = b"\x00\x00\x00\x00"

  full_key = bytearray(base_key)
  off = (segment - 1) * 4
  full_key[off:off + 4] = word
  full_key = bytes(full_key)

  if mode == 1:
    if erndb is not None:
      rndb = _tdes_d(full_key, bytes.fromhex(erndb))
    else:
      rndb = random_bytes(8)

    erndb_bin = _tdes_e(full_key, rndb)
    rndb_prime = rndb[1:] + rndb[:1]

    if blk1 is not None:
      rnda = _xor(_tdes_d(full_key, bytes.fromhex(blk1)), erndb_bin)
    else:
      rnda = random_bytes(8)

    cbc_blk1 = _tdes_e(full_key, _xor(rnda, erndb_bin))
    cbc_blk2 = _tdes_e(full_key, _xor(rndb_prime, cbc_blk1))

    return "$mfulc$%d$%d$%d$%s$%s$%s$%s" % (
      mode, segment, lfsr, erndb_bin.hex(), cbc_blk1.hex(), cbc_blk2.hex(), bytes(base_key).hex())

  return "$mfulc$%d$%d$%d$%s$%s$%s$%s" % (
    mode, segment, lfsr, erndb or "00" * 8, blk1 or "00" * 8, blk2 or "00" * 8, bytes(base_key).hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$mfulc$"):
    return None

  f = hash_in.split("$")

  if len(f) < 9:
    return None

  return (module_generate_hash(word, None, f[2], f[3], f[4], f[5], f[6], f[7], f[8]), word)
