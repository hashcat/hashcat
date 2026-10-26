#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64

from argon2.low_level import Type, hash_secret_raw

from lib.test_helpers import random_number

# Argon2id in the PHC string form. The memory cost m is in KiB, the same unit the perl passes to
# Crypt::Argon2 as "<m>k", and the digest length defaults to 16 or 32 bytes.


def b64_nopad(raw):
  return base64.b64encode(raw).rstrip(b"=").decode("ascii")


def b64_decode(text):
  pad = "=" * ((4 - len(text) % 4) % 4)

  return base64.b64decode(text + pad)


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, m=None, t=None, p=None, length=None):
  m = 65536 if m is None else int(m)
  t = 3 if t is None else int(t)
  p = 1 if p is None else int(p)
  length = random_number(1, 2) * 16 if length is None else int(length)

  salt_bin = bytes.fromhex(salt)

  digest_bin = hash_secret_raw(word, salt_bin, time_cost=t, memory_cost=m,
                               parallelism=p, hash_len=length, type=Type.ID, version=19)

  return "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s" % (m, t, p, b64_nopad(salt_bin), b64_nopad(digest_bin))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if not hash_in.startswith("$argon2id$"):
    return None

  fields = hash_in.split("$")

  if len(fields) < 6:
    return None

  _, signature, version, config, salt, digest = fields[:6]

  if version != "v=19":
    return None

  config_parts = config.split(",")

  if len(config_parts) != 3:
    return None

  m = config_parts[0].split("=")[1]
  t = config_parts[1].split("=")[1]
  p = config_parts[2].split("=")[1]

  salt_bin   = b64_decode(salt)
  digest_bin = b64_decode(digest)

  new_hash = module_generate_hash(word, salt_bin.hex(), m, t, p, len(digest_bin))

  return (new_hash, word)
