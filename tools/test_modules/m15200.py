#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, encrypted=None):
  if iterations is None:
    iterations = 5000

  iterations = int(iterations)

  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, 32)

  data = ('{\n'
          '"guid" : "00000000-0000-0000-0000-000000000000",\n'
          '"sharedKey" : "00000000-0000-0000-0000-000000000000",\n'
          '"options" : {"pbkdf2_iterations":%d,"fee_policy":0,"html5_notifications":false,'
          '"logout_time":600000,"tx_display":0,"always_keep_local_backup":false}' % iterations)

  data = data.encode("ascii")

  if encrypted is None:
    encrypted = AES.new(key, AES.MODE_CBC, salt_bin).encrypt(pad(data, 16)).hex()

  combined = salt + encrypted

  return "$blockchain$v2$%d$%s$%s" % (iterations, len(combined) // 2, combined)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  fields = hash_in.split("$")

  # ['', 'blockchain', 'v2', iterations, data_len, data]
  if len(fields) != 6:
    return None

  if fields[1] != "blockchain" or fields[2] != "v2":
    return None

  iterations = fields[3]
  data_len   = fields[4]
  data       = fields[5]

  if int(data_len) * 2 != len(data):
    return None

  salt      = data[0:32]
  encrypted = data[32:]

  new_hash = module_generate_hash(word, salt, iterations, encrypted)

  return (new_hash, word)
