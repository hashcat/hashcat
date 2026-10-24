#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.md5crypt import md5_crypt
from lib.test_helpers import random_mixedcase_string, split_hash_word, runtime_scrypt_n


# Cisco IOS XE "convoluted Type 9": $14$<type5 salt>$<type9 salt>$<digest>.
# scrypt(md5_crypt(password, type5_salt), type9_salt, N=16384, r=1, p=1). IOS XE
# auto-converts a Type 5 (MD5-crypt) secret to this on upgrade to Gibraltar 16.12.x+,
# running scrypt over the existing Type 5 hash string because the plaintext is gone.

CISCO = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [14, 14],
      },
      'optimized': None,
      'combined_length': None,
    },
    'runtime': {'compiled_cost': True, 'limit': 1024, 'scrypt': True},
    'normal': {'parameters': {'scrypt_n': 16384}},
  }


ITERATION_DEFAULTS = module_test_properties()['normal']['parameters']
SCRYPT_N = runtime_scrypt_n(ITERATION_DEFAULTS['scrypt_n'])


def module_generate_hash(word, salt, iterations=None, type5_salt=None):
  type9_salt = salt

  if type5_salt is None:
    type5_salt = random_mixedcase_string(4)

  h = md5_crypt(b"$1$", 1000, word, type5_salt.encode("latin-1")).encode("latin-1")

  key = hashlib.scrypt(h, salt=type9_salt.encode(), n=SCRYPT_N, r=1, p=1, dklen=32, maxmem=(128 * 16384 * 2))

  digest = base64.b64encode(key).decode()[:43].translate(CISCO)

  return "$14$%s$%s$%s" % (type5_salt, type9_salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$14$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 5 or len(fields[3]) != 14:
    return None

  type5_salt = fields[2]
  type9_salt = fields[3]

  return (module_generate_hash(word, type9_salt, None, type5_salt), word)
