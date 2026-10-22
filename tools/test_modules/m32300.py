#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import os

from lib.test_helpers import random_number, random_numeric_string

# EmpireCMS: md5 (salt2 . s1 . md5 (md5 (md5 (pass) . salt1) . s2 . salt1)), with two fixed
# application salts s1 and s2. salt2 is stored, drawn at random when absent. The optimized kernel
# caps salt2 at a shorter length, which IS_OPTIMIZED selects, matching the perl oracle.

EMPIRE_SALT1 = "E!m^p-i(r#e.C:M?S"
EMPIRE_SALT2 = "d)i.g^o-d"


def _md5_hex(data):
  return hashlib.md5(data).hexdigest()


def module_constraints():
  return [[0, 256], [0, 246], [0, 31], [0, 41], [-1, -1]]


def module_generate_hash(word, salt1, salt2=None):
  salt2_max_len = 33 if os.environ.get("IS_OPTIMIZED", "1") == "1" else 238

  # salt2 is drawn only when the field is absent. The perl oracle also redraws a "0" or "" here,
  # its 'shift || random', but a drawn "0" then cannot be verified back, so an explicit value is
  # kept and only a fresh generation (salt2 is None) draws one.
  if salt2 is None:
    salt2 = random_numeric_string(random_number(0, salt2_max_len))

  inner = _md5_hex((_md5_hex(word) + salt1).encode())

  digest = _md5_hex((salt2 + EMPIRE_SALT1 + inner + EMPIRE_SALT2 + salt1).encode())

  return "%s:%s:%s" % (digest, salt1, salt2)


def module_verify_hash(line):
  # the hash itself carries two colons (digest:salt1:salt2), so the password is field four
  parts = line.split(b":")

  if len(parts) < 4:
    return None

  salt1 = parts[1].decode(errors="replace")
  salt2 = parts[2].decode(errors="replace")
  word = parts[3]

  return (module_generate_hash(word, salt1, salt2), word)
