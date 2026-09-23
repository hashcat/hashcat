#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_word

# Python Werkzeug md5 (legacy): md5$salt$HMAC-MD5(key = salt, message = password), what
# generate_password_hash (pw, method="md5") gave before werkzeug 2.3 removed it.


def module_constraints():
  return [[0, 256], [0, 256], [0, 31], [0, 51], [0, 82]]


def module_generate_hash(word, salt, iterations=None):
  return "md5$%s$%s" % (salt, hmac.new(salt.encode(), word, hashlib.md5).hexdigest())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 3 or data[0] != "md5":
    return None

  return (module_generate_hash(word, data[1]), word)
