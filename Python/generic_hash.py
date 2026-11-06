#!/usr/bin/env python3

# The plugin -m 73000 loads unless --bridge-parameter1 names another one. Copy it, change calc_hash()
# and the self-test pair, and load the copy with --bridge-parameter1 path/to/copy.py.
#
# hashcat runs one copy of this file in a separate Python process per CPU thread, so calc_hash() needs
# no locking and anything it imports only has to work in an ordinary Python process.

import hashlib
import struct

import hcshared

# A hash and password that calc_hash() must reproduce. hashcat checks this pair before every run.

ST_HASH = "33522b0fd9812aa68586f66dba7c17a8ce64344137f9c7d8b11f32a6921c22de*9348746780603343"
ST_PASS = "hashcat"


# The hash of one candidate. Return the part of the hash line before the '*', as hashcat will compare
# it, or a list of up to 32 such values when one password can match in several forms.

def calc_hash(password: bytes, salt: dict) -> str:
  salt_buf = hcshared.get_salt_buf(salt)

  digest = hashlib.sha256(salt_buf + password)

  for i in range(10000):
    digest = hashlib.sha256(digest.digest())

  return digest.hexdigest()


# Optional. Converts the module's esalt buffer into one Python object per hash. The generic modes keep
# the hash line and its salt there, which is what hcshared.get_salt_buf() reads back.

def extract_esalts(esalts_buf: bytes) -> list:
  esalts = []

  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("1024s I 1024s I", esalts_buf):
    esalts.append({ "hash_buf": hash_buf[0:hash_len], "salt_buf": salt_buf[0:salt_len] })

  return esalts
