#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_hex_string, random_number, split_hash_word, test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'ci_seconds': {'opt': 1, 'pure': 85, 'bridge': 40, 'edge': 108}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 32, 'edge': 92},
    },
  }


# AxCrypt 1.x. The word's SHA1 xored with the salt gives a 16 byte AES key. The DEK is wrapped with
# an iterated AES key wrap. Byte slicing and the truncating string xor follow the perl one for one.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def _xor(a, b):
  # perl string xor keeps the length of the longer operand, the shorter padded with zero bytes
  n = max(len(a), len(b))

  a = a + b"\x00" * (n - len(a))
  b = b + b"\x00" * (n - len(b))

  return bytes(x ^ y for x, y in zip(a, b))


def get_random_axcrypt_salt():
  mysalt = random_bytes(16).hex()

  iteration = random_number(6, 99999)

  return "%d*%s" % (iteration, mysalt)


def module_generate_hash(word, salt=None, param=None, iterations=None):
  if salt is None or len(salt) == 0:
    salt = get_random_axcrypt_salt()

  salt_arr = salt.split("*")

  iteration = int(salt_arr[0]) if iterations is None else int(iterations)
  mysalt = bytes.fromhex(salt_arr[1])

  iv = "a6a6a6a6a6a6a6a6"

  kek = hashlib.sha1(word).digest()
  kek = _xor(kek, mysalt)[0:16]

  aes = AES.new(kek, AES.MODE_ECB)

  r = ['', b'', b'']

  if param is not None:
    param = bytes.fromhex(param)

    a = param[0:8]

    r[1] = param[8:16]
    r[2] = param[16:24]

    for j in range(iteration - 1, -1, -1):
      a = _xor(a[0:8], struct.pack("<i", 2 * j + 2))

      b = r[2]

      a = aes.decrypt((a + b + b"\x00" * 16)[0:16])

      r[2] = a[8:16]

      a = _xor(a[0:8], struct.pack("<i", 2 * j + 1))

      b = r[1]

      a = aes.decrypt((a + b + b"\x00" * 16)[0:16])

      r[1] = a[8:16]

    if a.find(b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6") != 0:
      # fake wrong values so the hash cannot round trip
      r = ['', b"\x00" * 8, b"\x00" * 8]
      a = b"\x00" * 16
  else:
    dek = bytes.fromhex(random_hex_string(32))

    r = ['', dek[0:8], dek[8:16]]
    a = bytes.fromhex(iv)

  for j in range(iteration):
    b = aes.encrypt((a + r[1] + b"\x00" * 16)[0:16])

    a = _xor(b[0:8], struct.pack("<q", 2 * j + 1))

    r[1] = b[8:16]

    b = aes.encrypt((a + r[2] + b"\x00" * 16)[0:16])

    a = _xor(b[0:8], struct.pack("<q", 2 * j + 2))

    r[2] = b[8:16]

  wrapped_key = (a + r[1][0:8] + r[2][0:8]).hex()

  mysalt = mysalt.hex()

  return "$axcrypt$*1*%d*%s*%s" % (iteration, mysalt, wrapped_key)


def module_verify_hash(line):
  parsed = split_hash_word(line)

  if parsed is None:
    return None

  hash_in, word = parsed

  data = hash_in.split("*")

  if len(data) != 5:
    return None

  signature, _version, iteration, mysalt, digest = data

  if signature != "$axcrypt$":
    return None

  if len(mysalt) != 32:
    return None

  if len(digest) != 48:
    return None

  salt = iteration + "*" + mysalt

  new_hash = module_generate_hash(word, salt, digest)

  return (new_hash, word)
