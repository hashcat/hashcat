#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import re

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, split_hash_word

# OSDP Secure Channel. S-ENC is the SCBK encrypting 0x01 0x82 and the first 6 bytes of RND.A, zero
# padded to a block. The client cryptogram the PD returns in osdp_CCRYPT is S-ENC encrypting
# RND.A . RND.B.

LINE = re.compile(r"^\$osdp\$([0-9a-fA-F]{16})\*([0-9a-fA-F]{16})\*([0-9a-fA-F]{32})$")


def module_test_properties():
  return {
    'constraints': {
      'pure': None,
      'optimized': {
        'password_length': [16, 16],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, rnd_a=None, rnd_b=None):
  if len(word) != 16:
    return None

  if rnd_a is None:
    rnd_a = random_bytes(8)

  if rnd_b is None:
    rnd_b = random_bytes(8)

  s_enc = AES.new(word, AES.MODE_ECB).encrypt(b"\x01\x82" + rnd_a[0:6] + b"\x00" * 8)

  cryptogram = AES.new(s_enc, AES.MODE_ECB).encrypt(rnd_a + rnd_b)

  return "$osdp$%s*%s*%s" % (rnd_a.hex(), rnd_b.hex(), cryptogram.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  m = LINE.match(hash_in)

  if m is None:
    return None

  if len(word) != 16:
    return None

  rnd_a = bytes.fromhex(m.group(1))
  rnd_b = bytes.fromhex(m.group(2))

  return (module_generate_hash(word, "", rnd_a, rnd_b), word)
