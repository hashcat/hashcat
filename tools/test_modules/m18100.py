#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import re

from lib.test_helpers import split_hash_salt_word

# TOTP (HMAC-SHA1): six digits out of HMAC-SHA1 of the 30 second time step, keyed with the password.
# The salt is the time; the token is zero padded, the time is not.


def perl_int(text):
  # int () in perl reads the leading digits and ignores the rest

  m = re.match(r"\s*([+-]?\d+)", text)

  return int(m.group(1)) if m else 0


def module_constraints():
  return [[0, 256], [8, 12], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  time = perl_int(salt)

  step = (time // 30).to_bytes(8, "big")

  digest = hmac.new(word, step, hashlib.sha1).digest()

  offset = digest[-1] & 0xf

  token = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000

  return "%06d:%d" % (token, time)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
