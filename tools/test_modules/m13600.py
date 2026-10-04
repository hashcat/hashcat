#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import random

# WinZip AES. PBKDF2-HMAC-SHA1 over the salt yields, in one run, the encryption key, the
# authentication key and the two password verification bytes. The stored auth code is the first ten
# bytes of HMAC-SHA1 over the (here empty) data, keyed with the authentication half.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, param=None, param2=None, param3=None,
                         param4=None, param5=None, param6=None):
  iterations = 1000

  hash_type = 0 if param is None else int(param)

  # mode picks the AES strength (1, 2, 3 for 128, 192, 256), drawn from perl's own rand () when the
  # caller does not fix it, so this mode is not seedable, matching the .pm

  if param2 is None:
    mode = 1 + int(random.random() * 3)
  else:
    mode = int(param2)

  magic = 0 if param3 is None else int(param3)

  if param4 is not None:
    salt = param4

  salt = salt[:8 + (mode * 8)]

  compress_length = 0 if param5 is None else int(param5)

  data = b"" if param6 is None else param6

  key_len = (8 * (mode & 3) + 8) * 2

  out_len = key_len + 2

  salt_bin = bytes.fromhex(salt)

  key = hashlib.pbkdf2_hmac("sha1", word, salt_bin, iterations, out_len).hex()

  verify_bytes = key[-4:]

  key_bin = bytes.fromhex(key[key_len:key_len + key_len])

  auth = hmac.new(key_bin, data, hashlib.sha1).hexdigest()

  return "$zip2$*%u*%u*%u*%s*%s*%s*%s*%s*$/zip2$" % (
    hash_type, mode, magic, salt, verify_bytes, compress_length, data.hex(), auth[0:20])


def module_verify_hash(line):
  parts = line.split(b":")

  if len(parts) < 2:
    return None

  hash_in = parts[0].decode(errors="replace")
  word    = parts[1]

  fields = hash_in.split("*")

  if len(fields) != 10:
    return None

  if fields[0] != "$zip2$" or fields[9] != "$/zip2$":
    return None

  hash_type = fields[1]
  mode      = fields[2]
  magic     = fields[3]
  salt      = fields[4]
  length    = fields[6]
  data      = bytes.fromhex(fields[7])

  new_hash = module_generate_hash(word, salt, hash_type, mode, magic, salt, length, data)

  return (new_hash, word)
