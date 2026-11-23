#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib

from lib.test_helpers import test_iteration_parameters

# scrypt: SCRYPT:N:r:p:base64(salt):base64(key).


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [1, 15],
      },
      'optimized': None,
      'combined_length': None,
    },
    'reduced': {'parameters': {'scrypt_n': 1024}},
  }


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, n=None, r=8, p=1, scrypt_n=None):
  if n is None:
    n = 16384 if scrypt_n is None else scrypt_n

  n = int(n)

  salt_bytes = salt.encode("latin-1")

  key = hashlib.scrypt(word, salt=salt_bytes, n=n, r=r, p=p, dklen=32, maxmem=(128 * n * r * 2))

  return "SCRYPT:%d:%d:%d:%s:%s" % (n, r, p, base64.b64encode(salt_bytes).decode(), base64.b64encode(key).decode())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split(":")

  if len(fields) != 6 or fields[0] != "SCRYPT":
    return None

  try:
    n, r, p = int(fields[1]), int(fields[2]), int(fields[3])
    salt = base64.b64decode(fields[4]).decode("latin-1")
  except (ValueError, binascii.Error):
    return None

  return (module_generate_hash(word, salt, None, n, r, p), word)
