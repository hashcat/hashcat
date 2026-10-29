#!/usr/bin/env python3

##
## Author......: Deutsche Telekom Security GmbH
## License.....: MIT
##

import hashlib
import hmac
import struct

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number, split_hash_word


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, memory=None, parallelism=None,
                         algorithm=b"ssh-rsa", comment=None, public=None, encrypted=None,
                         argon2_type=None):
  passes = random_number(1, 3) if iterations is None else int(iterations)
  memory = (1 << random_number(8, 10)) if memory is None else int(memory)
  parallelism = random_number(1, 4) if parallelism is None else int(parallelism)
  argon2_type = random_number(0, 2) if argon2_type is None else int(argon2_type)
  salt_bin = bytes.fromhex(salt)

  derived = hash_secret_raw(word, salt_bin, passes, memory, parallelism, 80, Type(argon2_type), version=19)
  key, iv, mac_key = derived[:32], derived[32:48], derived[48:]

  comment = random_bytes(random_number(0, 64)) if comment is None else comment
  public = random_bytes(random_number(1, 512)) if public is None else public

  if encrypted is None:
    private = random_bytes(16 * random_number(1, 512))
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(private)
  else:
    private = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)

  fields = (algorithm, b"aes256-cbc", comment, public, private)
  message = b"".join(struct.pack(">I", len(field)) + field for field in fields)
  mac = hmac.new(mac_key, message, hashlib.sha256).hexdigest()

  return "$ppk$3*%s*%s*%s*%d*%d*%d*%s*%d*%s*%d*%s*%s*%d" % (
    algorithm.hex(), fields[1].hex(), comment.hex(), memory, passes, parallelism,
    salt_bin.hex(), len(public), public.hex(), len(encrypted), encrypted.hex(), mac, argon2_type)


def module_verify_hash(line):
  result = split_hash_word(line)

  if result is None:
    return None

  hash_str, word = result
  parts = hash_str.split("*")

  if len(parts) != 14 or parts[0] != "$ppk$3" or parts[2] != b"aes256-cbc".hex():
    return None

  try:
    algorithm = bytes.fromhex(parts[1])
    comment = bytes.fromhex(parts[3])
    public = bytes.fromhex(parts[9])
    encrypted = bytes.fromhex(parts[11])

    if len(public) != int(parts[8]) or len(encrypted) != int(parts[10]):
      return None

    if not encrypted or len(encrypted) % 16:
      return None

    new_hash = module_generate_hash(word, parts[7], iterations=parts[5], memory=parts[4],
                                     parallelism=parts[6], algorithm=algorithm, comment=comment,
                                     public=public, encrypted=encrypted, argon2_type=parts[13])
  except ValueError:
    return None

  return (new_hash, word)