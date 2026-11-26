#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# IKE-PSK for the 5300 (MD5) and 5400 (SHA-1) test modules. The salt is the eight hex fields of the
# exchange, colon separated; the key is HMAC (password, Ni | Nr), the hash HMAC (key, message).

import hashlib
import hmac

from lib.test_helpers import random_bytes, random_number

# The SA and ID payloads and the two nonces vary in length on the wire. Random lengths make the
# test check that each field comes back from hashcat with the length it went in with.


def random_salt():
  sizes = (128, 128, 8, 8, random_number(1, 160), random_number(1, 32), random_number(8, 27), random_number(8, 27))

  return ":".join(random_bytes(size).hex() for size in sizes)


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
