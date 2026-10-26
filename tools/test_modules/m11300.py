#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib.test_helpers import random_hex_string, random_number

# Bitcoin/Litecoin wallet.dat: SHA512 of the password plus salt, iterated, then AES-256-CBC over the
# master key. key is digest[0:32], iv is digest[32:48].


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, ckey=None, public_key=None, salt_iter=None, cry_master=None):
  if ckey is None:
    ckey = random_hex_string(96)

  if public_key is None:
    public_key = random_hex_string(66)

  if salt_iter is None:
    salt_iter = random_number(150000, 250000)

  salt_iter = int(salt_iter)

  digest = hashlib.sha512(word + bytes.fromhex(salt)).digest()

  for _ in range(1, salt_iter):
    digest = hashlib.sha512(digest).digest()

  key = digest[0:32]
  iv  = digest[32:48]

  if cry_master is None:
    data = random_hex_string(32).encode("ascii")
  else:
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes.fromhex(cry_master))

    if data.endswith(b"\x10" * 16):
      data = data[:-16]
    elif data.endswith(b"\x08" * 8):
      data = data[:-8]
    else:
      data = b"WRONG"

  cry_master = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16)).hex()

  return "$bitcoin$%d$%s$%d$%s$%d$%d$%s$%d$%s" % (
    len(cry_master), cry_master,
    len(salt), salt,
    salt_iter,
    len(ckey), ckey,
    len(public_key), public_key)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if not hash_in.startswith("$bitcoin$"):
    return None

  fields = hash_in.split("$")

  # ['', 'bitcoin', cry_master_len, cry_master, salt_len, salt, salt_iter, ckey_len, ckey,
  #  public_key_len, public_key]
  if len(fields) != 11:
    return None

  cry_master = fields[3]
  salt       = fields[5]
  salt_iter  = fields[6]
  ckey       = fields[8]
  public_key = fields[10]

  new_hash = module_generate_hash(word, salt, ckey, public_key, salt_iter, cry_master)

  return (new_hash, word)
