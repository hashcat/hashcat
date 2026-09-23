#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import crypt_r

from lib import yescrypt
from lib.test_helpers import random_string, split_hash_word

# gost-yescrypt, through libc crypt (): $gy$params$salt_b64$hash.


def module_constraints():
  return [[0, 256], [1, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, params="j9T"):
  if salt is None:
    salt = random_string(16)

  setting = "$gy$%s$%s$" % (params, yescrypt.encode64(salt.encode("latin-1")))

  return crypt_r.crypt(word.decode("latin-1"), setting)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$gy$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 5 or fields[1] != "gy":
    return None

  salt = yescrypt.decode64(fields[3]).decode("latin-1")

  return (module_generate_hash(word, salt, None, fields[2]), word)
