#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# SolarWinds Orion: SHA-512 of a 1024 byte PBKDF2-HMAC-SHA1 key, salted with the first 8 characters
# of the salt, padded out with a fixed string when it is shorter.


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  custom = (salt[:8] + "1244352345234")[:8]

  key = hashlib.pbkdf2_hmac("sha1", word, custom.encode("latin-1"), 1000, 1024)

  return "$solarwinds$0$%s$%s" % (salt, base64.b64encode(hashlib.sha512(key).digest()).decode())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 5 or data[1] != "solarwinds" or data[2] != "0" or len(data[3]) > 256 or len(data[4]) != 88:
    return None

  return (module_generate_hash(word, data[3]), word)
