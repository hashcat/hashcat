#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib.test_helpers import (
  random_bytes,
  random_lowercase_string,
  random_number,
)

# SecureZIP AES-128. The key is sha1 (word) folded through an ipad/opad pair, concatenated and
# truncated, then AES-CBC over 128 bytes of file data. Verify decrypts and checks that the trailing
# block is the standard PKCS#7 full block padding.

BIT_LEN = 128


def _derive_key(word, key_len):
  digest = hashlib.sha1(word).digest()

  ipad = bytes(b ^ 0x36 for b in digest) + b"\x36" * 44
  opad = bytes(b ^ 0x5c for b in digest) + b"\x5c" * 44

  key = hashlib.sha1(ipad).digest() + hashlib.sha1(opad).digest()

  return key[:key_len]


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, iv=None, data=None, file=None):
  key_len = BIT_LEN // 8

  is_decrypt = data is not None

  if not is_decrypt:
    iv = random_bytes(random_number(1, 16))
    data = random_bytes(128)
    file = random_lowercase_string(random_number(1, 16)) + ".txt"

  iv_mod = iv + b"\x00" * (16 - len(iv))

  key = _derive_key(word, key_len)

  if not is_decrypt:
    data = AES.new(key, AES.MODE_CBC, iv_mod).encrypt(pad(data, 16))
  else:
    data_decrypted = AES.new(key, AES.MODE_CBC, iv_mod).decrypt(data)

    # wrong password if the recovered tail is not a full block of PKCS#7 padding
    if data_decrypted[-16:] != b"\x10" * 16:
      data = b"fake"

  iv_padded = iv + b"\x00" * max(0, 12 - len(iv))

  return "$zip3$*0*1*%i*0*%s*%s*0*0*0*%s" % (BIT_LEN, iv_padded.hex(), data.hex(), file)


def module_verify_hash(line):
  if not line.startswith(b"$zip3$*0*1*"):
    return None

  idx = line.find(b":")

  if idx < 11:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split("*", 10)

  if len(fields) != 11:
    return None

  if fields[1] != "0" or fields[2] != "1" or fields[4] != "0":
    return None

  if fields[7] != "0" or fields[8] != "0" or fields[9] != "0":
    return None

  try:
    if int(fields[3]) != BIT_LEN:
      return None

    iv = bytes.fromhex(fields[5])
    data = bytes.fromhex(fields[6])
  except ValueError:
    return None

  file = fields[10]

  return (module_generate_hash(word, iv=iv, data=data, file=file), word)
