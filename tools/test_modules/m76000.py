#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64

from argon2.low_level import Type, hash_secret_raw

from lib.test_helpers import random_number, split_hash_word

# Argon2 (argon2id). The hash keeps the m/t/p cost parameters and the salt,
# all of which the verify path reads back so the same raw digest is recomputed.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def _b64(data):
  return base64.b64encode(data).decode("ascii").rstrip("=")


def module_generate_hash(word, salt, m=None, t=None, p=None):
  if m is None:
    m = 1 << random_number(12, 18)

  if t is None:
    t = random_number(1, 8)

  if p is None:
    p = random_number(1, 8)

  salt_bin = bytes.fromhex(salt)

  digest = hash_secret_raw(word, salt_bin, int(t), int(m), int(p), int(32), Type.ID, version=19)

  return "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s" % (int(m), int(t), int(p), _b64(salt_bin), _b64(digest))


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  if not (hash_str.startswith("$argon2id$")):
    return None

  data = hash_str.split("$")

  if len(data) != 6:
    return None

  version = data[2]
  config = data[3]
  salt = data[4]
  digest = data[5]

  if version != "v=19":
    return None

  cfg = config.split(",")

  if len(cfg) != 3:
    return None

  m = cfg[0].split("=")[1]
  t = cfg[1].split("=")[1]
  p = cfg[2].split("=")[1]

  salt_bin = base64.b64decode(salt + "=" * (-len(salt) % 4))
  digest_bin = base64.b64decode(digest + "=" * (-len(digest) % 4))

  if len(digest_bin) != 32
    return None

  new_hash = module_generate_hash(word, salt_bin.hex(), int(m), int(t), int(p))

  return (new_hash, word)
