#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from lib.test_helpers import utf16le

# Microsoft Online Account. The key is PBKDF2-HMAC-SHA256 over an empty salt, the password widened
# from its UTF-8 decoding to UTF-16LE. A fixed cleartext blob is AES-256-CBC encrypted with PKCS7
# padding and a zero IV. Verification decrypts the stored ciphertext, and when the recovered blob
# carries the magic marker it re-encrypts that instead.

IV = b"\x00" * 16
KEY_LEN = 32

DEFAULT_BLOB = bytes.fromhex("000000000100000000000000600000006000000000000000200000004000")
MAGIC = "\x00\x00\x00\x00\x01\x00\x00\x00".encode("latin-1").hex()


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, iterations=None, ct=None):
  if iterations is None or not re.match(r"^\d+$", str(iterations)):
    iter_n = 10000
  else:
    iter_n = int(iterations)

  # the kernel decodes the UTF-8 word rather than widening its bytes, and there is no optimized
  # kernel to follow the other way
  word_utf16le = utf16le(word, "utf-8")

  key = hashlib.pbkdf2_hmac("sha256", word_utf16le, b"", iter_n, KEY_LEN)

  if ct is not None:
    data_bin = bytes.fromhex(ct)

    try:
      pt_bin = unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(data_bin), 16)
    except ValueError:
      pt_bin = b""

    if pt_bin[:8].hex() == MAGIC:
      data_bin = pt_bin
  else:
    data_bin = DEFAULT_BLOB

  ct_bin = AES.new(key, AES.MODE_CBC, IV).encrypt(pad(data_bin, 16))

  return "$MSONLINEACCOUNT$0$%d$%s" % (iter_n, ct_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_str = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_str[:18] != "$MSONLINEACCOUNT$0":
    return None

  data = hash_str.split("$")

  if len(data) != 5:
    return None

  signature, hid, iterations, ct = data[1], data[2], data[3], data[4]

  if signature != "MSONLINEACCOUNT":
    return None

  if hid != "0":
    return None

  return (module_generate_hash(word, iterations, ct), word)
