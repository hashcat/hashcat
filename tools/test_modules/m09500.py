#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
from functools import partial

from Crypto.Cipher import AES

from lib import office
from lib.test_helpers import kernel_charset, split_hash_word, utf16le, iteration_override_enabled, runtime_iteration_limit


# MS Office 2010: 100000 rounds of SHA1, two block keys, AES-128-CBC with the salt as IV.

CHARSET = kernel_charset()

IN_KEY = b"\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79"
VAL_KEY = b"\xd7\xaa\x0f\x6d\x30\x61\x34\x4e"


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 15],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 100000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']


COMPUTE_ITERATIONS = int

if iteration_override_enabled():
  COMPUTE_ITERATIONS = partial(min, runtime_iteration_limit())


def module_generate_hash(word, salt, iterations=None, param=None):
  iterations = ITERATION_DEFAULTS['iterations'] if iterations is None else int(iterations)

  salt_bin = bytes.fromhex(salt)

  tmp = office.iterated_key(hashlib.sha1, salt_bin, utf16le(word, CHARSET), COMPUTE_ITERATIONS(iterations))

  key1 = hashlib.sha1(tmp + IN_KEY).digest()[:16]
  key2 = hashlib.sha1(tmp + VAL_KEY).digest()[:16]

  encdata = AES.new(key1, AES.MODE_CBC, salt_bin).decrypt(bytes.fromhex(param)) if param else b"A" * 16

  data1 = encdata
  data2 = hashlib.sha1(data1[:16]).digest()

  enc1 = AES.new(key1, AES.MODE_CBC, salt_bin).encrypt(data1).hex()
  enc2 = AES.new(key2, AES.MODE_CBC, salt_bin).encrypt((data2 + b"\x00" * 12)[:32] if len(data2) % 16 else data2).hex()[:64]

  return "$office$*2010*%d*128*16*%s*%s*%s" % (iterations, salt, enc1, enc2)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) < 8 or data[1] != "2010" or data[3] != "128":
    return None

  return (module_generate_hash(word, data[5], data[2], data[6]), word)
