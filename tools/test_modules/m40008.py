#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_salt_word

# Oracle o5logon, the AUTH_SESSKEY padding check. The key is sha1 (pass . AUTH_VFR_DATA) zero
# extended to 24 bytes, which selects AES-192. A server whose capture this mode can crack pads the
# 48 byte AUTH_SESSKEY with 8 bytes of 0x08, so decrypting its last block leaves that padding in the
# second half. Generating a line therefore means encrypting a plaintext that ends that way.

LINE = re.compile(r"^\$o5logon\$([0-9a-fA-F]{96})\*([0-9a-fA-F]{20})$")

SESSKEY_LEN = 48
VFR_LEN     = 10


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def o5logon_key(word, vfr):
  return hashlib.sha1(word + vfr).digest() + b"\x00" * 4


def module_generate_hash(word, salt, vfr=None):
  if vfr is None:
    # the salt test.py supplies is text of any length, so it is hashed down to the 10 bytes a real
    # AUTH_VFR_DATA carries
    vfr = hashlib.sha1(salt.encode()).digest()[0:VFR_LEN]

  # 40 bytes of filler, then the padding a crackable capture ends with. The filler is derived from
  # the key so that a line is reproducible from its password and salt.
  key = o5logon_key(word, vfr)

  filler = hashlib.sha256(key).digest() + hashlib.sha256(key[::-1]).digest()

  pt = filler[0:SESSKEY_LEN - 8] + b"\x08" * 8

  sesskey = AES.new(key, AES.MODE_CBC, b"\x00" * 16).encrypt(pt)

  return "$o5logon$%s*%s" % (sesskey.hex().upper(), vfr.hex().upper())


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, salt, word = parts

  if LINE.match(hash_in) is None:
    return None

  return (module_generate_hash(word, salt), word)
