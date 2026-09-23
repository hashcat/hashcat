#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import split_hash_salt_word

# IPMI2 RAKP HMAC-MD5. The mode needs a salt of 58 bytes or more, which the optimized kernel's 55
# cannot hold, so a short salt is padded with 116 zeros; either way it is cut to an even length and
# used as hex.


def module_constraints():
  return [[0, 256], [116, 148], [0, 55], [0, 31], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if len(salt) < 32:
    salt += "0" * 116

  salt = salt[:len(salt) - (len(salt) % 2)]

  return "%s:%s" % (hmac.new(word, bytes.fromhex(salt), hashlib.md5).hexdigest(), salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    return (module_generate_hash(word, salt), word)
  except ValueError:
    return None
