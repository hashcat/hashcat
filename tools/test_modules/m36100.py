#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import libcrypt
from lib import yescrypt
from lib.test_helpers import random_string, split_hash_word, test_iteration_parameters

# yescrypt, through libc crypt (): $y$params$salt_b64$hash. libcrypt calls the same crypt_r () the
# perl reached, so the result matches where libxcrypt is present.


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [1, 64],
      },
      'optimized': None,
      'combined_length': None,
    },
    'reduced': {'kernel_accel': 8, 'parameters': {'scrypt_n': 1024}},
  }


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, params=None, scrypt_n=None):
  if params is None:
    params = "j9T" if scrypt_n is None else "j%sT" % yescrypt.ITOA64[int(scrypt_n).bit_length() - 2]

  if salt is None:
    salt = random_string(16)

  setting = "$y$%s$%s$" % (params, yescrypt.encode64(salt.encode("latin-1")))

  return libcrypt.crypt(word.decode("utf-8"), setting)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$y$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 5 or fields[1] != "y":
    return None

  salt = yescrypt.decode64(fields[3]).decode("latin-1")

  return (module_generate_hash(word, salt, None, fields[2]), word)
