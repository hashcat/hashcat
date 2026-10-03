#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# IKE-PSK for the 5300 (MD5) and 5400 (SHA-1) test modules. The salt is the eight hex fields of the
# exchange, colon separated; the key is HMAC (password, Ni | Nr), the hash HMAC (key, message).

import hashlib
import hmac

from lib.test_helpers import random_bytes

# where each of the eight fields sits in the 440 random message bytes and the 40 nonce bytes

MSG_FIELDS = ((0, 128), (128, 128), (256, 8), (264, 8), (272, 160), (432, 8))


def random_salt():
  nr = random_bytes(40).hex()
  msg = random_bytes(440).hex()

  fields = [msg[2 * off:2 * (off + size)] for off, size in MSG_FIELDS] + [nr[:40], nr[40:]]

  return ":".join(fields)


def generate_hash(algo, word, salt):
  if not salt:
    salt = random_salt()

  fields = salt.split(":")

  msg = bytes.fromhex("".join(fields[0:6]))
  nr = bytes.fromhex(fields[6] + fields[7])

  key = hmac.new(word, nr, algo).digest()

  return "%s:%s" % (salt, hmac.new(key, msg, algo).hexdigest())


def verify_hash(algo, line):
  data = line.split(b":", 9)

  if len(data) != 10:
    return None

  salt = b":".join(data[0:8]).decode()
  word = data[9]

  try:
    return (generate_hash(algo, word, salt), word)
  except (ValueError, IndexError):
    return None
