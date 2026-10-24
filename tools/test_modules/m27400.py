#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string, runtime_iterations


# VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC). The key encrypts a fixed 16 byte marker; only the
# first cipher block is stored, so the padding of the rest does not matter.

DATA = b"type=key:cipher="

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'limit': 2},
    'normal': {'parameters': {'iterations': 10000}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
ITERATIONS = runtime_iterations(ITERATION_DEFAULTS['iterations'], initial=1)


def module_generate_hash(word, salt_str, ct_str=None):
  iv_str = ct_str[:32] if ct_str is not None else random_hex_string(32)

  salt = bytes.fromhex(salt_str)
  iv = bytes.fromhex(iv_str)

  key = hashlib.pbkdf2_hmac("sha1", word, salt, ITERATIONS, 32)

  encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(DATA).hex()

  return "$vmx$0$%s$%s$%s%s" % (ITERATION_DEFAULTS['iterations'], salt.hex(), iv.hex(), encrypted[:32])


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("$")

  if len(data) != 6:
    return None

  _, signature, version, rounds, salt, ct = data

  if signature != "vmx" or version != "0" or rounds != "10000" or len(ct) != 64:
    return None

  return (module_generate_hash(word, salt, ct), word)
