#!/usr/bin/env python3

##
## Author......: Deutsche Telekom Security GmbH
## License.....: MIT
##

import hashlib
import hmac
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number, split_hash_word


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, algorithm=b"ssh-rsa", comment=None,
                         public=None, encrypted=None):
  key = (hashlib.sha1(b"\x00\x00\x00\x00" + word).digest()
         + hashlib.sha1(b"\x00\x00\x00\x01" + word).digest())[:32]
  mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + word).digest()

  comment = random_bytes(random_number(0, 64)) if comment is None else comment
  public = random_bytes(random_number(1, 512)) if public is None else public

  if encrypted is None:
    private = bytes.fromhex(salt) + random_bytes(16 * random_number(0, 511))
    encrypted = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(private)
  else:
    private = AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(encrypted)

  fields = (algorithm, b"aes256-cbc", comment, public, private)
  message = b"".join(struct.pack(">I", len(field)) + field for field in fields)
  mac = hmac.new(mac_key, message, hashlib.sha1).hexdigest()

  return "$ppk$2*%s*%s*%s*%d*%s*%d*%s*%s" % (
    algorithm.hex(), fields[1].hex(), comment.hex(), len(public), public.hex(),
    len(encrypted), encrypted.hex(), mac)


def module_verify_hash(line):
  result = split_hash_word(line)

  if result is None:
    return None

  hash_str, word = result
  parts = hash_str.split("*")

  if len(parts) != 9 or parts[0] != "$ppk$2" or parts[2] != b"aes256-cbc".hex():
    return None

  try:
    algorithm = bytes.fromhex(parts[1])
    comment = bytes.fromhex(parts[3])
    public = bytes.fromhex(parts[5])
    encrypted = bytes.fromhex(parts[7])

    if len(public) != int(parts[4]) or len(encrypted) != int(parts[6]):
      return None

    if not encrypted or len(encrypted) % 16:
      return None

    new_hash = module_generate_hash(word, "", algorithm=algorithm, comment=comment,
                                     public=public, encrypted=encrypted)
  except ValueError:
    return None

  return (new_hash, word)