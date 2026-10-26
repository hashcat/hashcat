#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import hmac
import re

from lib.test_helpers import split_hash_salt_word

# TOTP (HMAC-SHA1): six digits out of HMAC-SHA1 of the 30 second time step, keyed with the password.
# The salt is the time; the token is zero padded, the time is not.


def perl_int(text):
  # int () in perl reads the leading digits and ignores the rest

  m = re.match(r"\s*([+-]?\d+)", text)

  return int(m.group(1)) if m else 0


def module_constraints():
  return [[0, 256], [8, 12], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  time = perl_int(salt)

  step = (time // 30).to_bytes(8, "big")

  digest = hmac.new(word, step, hashlib.sha1).digest()

  offset = digest[-1] & 0xf

  token = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000

  return "%06d:%d" % (token, time)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  token, salt, word = parts

  target = "%s:%s" % (token, salt)

  # The token is '% 1000000', so many secrets map to the same six digits: hashcat reports whichever
  # it reaches first, not necessarily the generated one. It also prints the recovered secret base32
  # encoded, while the generator round-trips the raw secret bytes. Try the base32 decoding first and
  # fall back to the raw bytes, accepting whichever reproduces the token. The word is handed back
  # unchanged so hash:word still reconstructs.
  for key in _secret_candidates(word):
    if module_generate_hash(key, salt) == target:
      return (target, word)

  return (module_generate_hash(word, salt), word)


def _secret_candidates(word):
  decoded = _b32decode(word)

  if decoded is not None:
    return [decoded, word]

  return [word]


def _b32decode(word):
  try:
    text = word.decode("ascii")
  except UnicodeDecodeError:
    return None

  if len(text) == 0 or len(text) % 8 != 0 or re.fullmatch(r"[A-Z2-7]+=*", text) is None:
    return None

  try:
    return base64.b32decode(text)
  except (ValueError, binascii.Error):
    return None
