#!/usr/bin/env python3

# Helpers a plugin can import. hcworker.py uses extract_salts() to hand every plugin its salts.

import struct

# salt_t from OpenCL/inc_types.h, 572 bytes. The "=" is what keeps it that way: the fields happen to
# need no padding today, so native alignment gives the same 572, but a u64 added to the struct would
# start inserting padding here and shift every field a plugin reads. hcworker.py checks the size
# against the one hashcat states, so a layout change is reported rather than silently decoded wrong.

SALT_T = struct.Struct("=256s 256s I I I I I 8s I I I I I I I I")


# Converts a buffer of salt_t entries into one dictionary per salt. The fixed fields stay at the top
# level, and a plugin's own extract_esalts() result goes under "esalt".

def extract_salts(salts_buf: bytes) -> list:
  salts = []

  for salt_buf, salt_buf_pc, salt_len, salt_len_pc, salt_iter, salt_iter2, salt_dimy, salt_sign, salt_repeats, orig_pos, digests_cnt, digests_done, digests_offset, scrypt_N, scrypt_r, scrypt_p in SALT_T.iter_unpack(salts_buf):
    salts.append({
      "salt_buf":       salt_buf[0:salt_len],
      "salt_buf_pc":    salt_buf_pc[0:salt_len_pc],
      "salt_iter":      salt_iter,
      "salt_iter2":     salt_iter2,
      "salt_dimy":      salt_dimy,
      "salt_sign":      salt_sign,
      "salt_repeats":   salt_repeats,
      "orig_pos":       orig_pos,
      "digests_cnt":    digests_cnt,
      "digests_done":   digests_done,
      "digests_offset": digests_offset,
      "scrypt_N":       scrypt_N,
      "scrypt_r":       scrypt_r,
      "scrypt_p":       scrypt_p,
      "esalt":          None,
    })

  return salts


# The generic modes keep the salt from the hash line in their esalt and use the fixed salt_buf only
# to group hashes, so for them the salt a plugin wants is the esalt's.

def get_salt_buf(salt: dict) -> bytes:
  return salt["esalt"]["salt_buf"]


def get_salt_buf_pc(salt: dict) -> bytes:
  return salt["salt_buf_pc"]


def get_salt_iter(salt: dict) -> int:
  return salt["salt_iter"]


def get_salt_iter2(salt: dict) -> int:
  return salt["salt_iter2"]


def get_salt_sign(salt: dict) -> bytes:
  return salt["salt_sign"]


def get_salt_repeats(salt: dict) -> int:
  return salt["salt_repeats"]


def get_orig_pos(salt: dict) -> int:
  return salt["orig_pos"]


def get_digests_cnt(salt: dict) -> int:
  return salt["digests_cnt"]


def get_digests_done(salt: dict) -> int:
  return salt["digests_done"]


def get_digests_offset(salt: dict) -> int:
  return salt["digests_offset"]


def get_scrypt_N(salt: dict) -> int:
  return salt["scrypt_N"]


def get_scrypt_r(salt: dict) -> int:
  return salt["scrypt_r"]


def get_scrypt_p(salt: dict) -> int:
  return salt["scrypt_p"]
