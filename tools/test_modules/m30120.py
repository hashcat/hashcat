#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_word

# Python Werkzeug sha256 (legacy): sha256$salt$HMAC-SHA256(key = salt, message = password), what
# generate_password_hash (pw, method="sha256") gave before werkzeug 2.3 removed it.


def module_constraints():
  return [[0, 256], [0, 256], [0, 31], [0, 51], [0, 82]]


def module_generate_hash(word, salt, iterations=None):
  return "sha256$%s$%s" % (salt, hmac.new(salt.encode(), word, hashlib.sha256).hexdigest())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 3 or data[0] != "sha256":
    return None

  return (module_generate_hash(word, data[1]), word)
