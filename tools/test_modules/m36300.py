#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import crypt_r

from lib import yescrypt
from lib.test_helpers import random_string, split_hash_word

# scrypt through libc crypt (), the $7$ form: $7$<N><r><p><salt>$hash, N as one crypt64 digit and r
# and p as five each. The self-test parameters are fixed at N=2^14, r=8, p=1.


def module_constraints():
  return [[0, 256], [1, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, n_log2=14, r=8, p=1):
  if salt is None:
    salt = random_string(12)

  setting = "$7$%s%s%s%s$" % (yescrypt.ITOA64[n_log2], yescrypt.encode_uint(r, 5),
                              yescrypt.encode_uint(p, 5), salt)

  return crypt_r.crypt(word.decode("latin-1"), setting)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$7$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 4 or fields[1] != "7" or len(fields[2]) <= 11:
    return None

  setting = fields[2]

  n_log2 = yescrypt.ITOA64.index(setting[0])
  r = yescrypt.decode_uint(setting[1:6])
  p = yescrypt.decode_uint(setting[6:11])
  salt = setting[11:]

  return (module_generate_hash(word, salt, None, n_log2, r, p), word)
