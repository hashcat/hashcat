#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from Crypto.Cipher import AES

from lib.test_helpers import random_hex_string

# SecureCRT "Config Passphrase" (=02). The SHA-256 of the password is both the AES-256-CBC key and
# part of the plaintext, which is length prefixed, followed by the password, its digest and random
# padding to a 16 byte boundary. The IV is fixed to zero.

_RE = re.compile(rb'S:.Config.Passphrase.=02:(.*):(.*)')


def _calculate_padding(length, blocksize=32, minpadding=16):
  padded_len = length + minpadding
  finalpadded = ((padded_len - 1) | (blocksize - 1)) + 1

  return finalpadded - length


def _get_aes(word):
  key = hashlib.sha256(word).hexdigest()

  return AES.new(bytes.fromhex(key), AES.MODE_CBC, b"\x00" * 16)


def module_constraints():
  return [[0, 55], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, padding=None, param=None):
  total_len = (len(word) * 2) + 8 + 64

  if padding is None:
    padding = random_hex_string(_calculate_padding(total_len))

  if len(padding) == 0:
    padding = random_hex_string(_calculate_padding(total_len))

  digest = hashlib.sha256(word).hexdigest()
  wlen = "%02d" % len(word)
  paddedlen = "%02x000000" % int(wlen)
  hexofword = word.hex()
  plaintext = paddedlen + hexofword + digest + padding

  ciphertext = _get_aes(word).encrypt(bytes.fromhex(plaintext))

  return 'S:"Config Passphrase"=02:%s' % ciphertext.hex()


def module_verify_hash(line):
  m = _RE.search(line)

  if not m:
    return None

  hash_hex = m.group(1).decode(errors="replace")
  word = m.group(2)

  decrypted = _get_aes(word).decrypt(bytes.fromhex(hash_hex))
  plaintext_hex = decrypted.hex()
  passlen = int(plaintext_hex[0:2], 16)
  padding = plaintext_hex[8 + 2 * passlen + 64:]

  new_hash = module_generate_hash(word, padding)

  return (new_hash, word)
