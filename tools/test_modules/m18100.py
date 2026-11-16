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

# TOTP (HMAC-SHA1): six digits out of HMAC-SHA1 of the 30 second time step, keyed with the password.
# The salt is the time; the token is zero padded, the time is not. A hash may carry the time step
# in seconds as a third field, default 30. The generator uses a 60 second step for even times and
# the default for odd ones, and hashcat prints the step only when it is not 30, so the parity of
# the time says which form a line is in.


def perl_int(text):
  # int () in perl reads the leading digits and ignores the rest

  m = re.match(r"\s*([+-]?\d+)", text)

  return int(m.group(1)) if m else 0


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [8, 12],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  time = perl_int(salt)

  step = 60 if time % 2 == 0 else 30

  counter = (time // step).to_bytes(8, "big")

  digest = hmac.new(word, counter, hashlib.sha1).digest()

  offset = digest[-1] & 0xf

  token = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000

  if step == 30:
    return "%06d:%d" % (token, time)

  return "%06d:%d:%d" % (token, time, step)


def module_verify_hash(line):
  parts = line.split(b":")

  if len(parts) < 3:
    return None

  token = parts[0].decode(errors="replace")
  salt = parts[1].decode(errors="replace")

  time = perl_int(salt)

  if time % 2 == 0:
    if len(parts) < 4 or parts[2].isdigit() is False:
      return None

    step = parts[2].decode(errors="replace")
    word = b":".join(parts[3:])

    target = "%s:%s:%s" % (token, salt, step)
  else:
    word = b":".join(parts[2:])

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
