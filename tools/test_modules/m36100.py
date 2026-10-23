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


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(36100)


def module_constraints():
  return [[0, 256], [1, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, params="j9T", n_log2=None):
  if salt is None:
    salt = random_string(16)

  if n_log2 is not None:
    params = "j" + yescrypt.ITOA64[int(n_log2) - 1] + "T"

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
