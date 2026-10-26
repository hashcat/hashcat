#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import hmac
import json

from lib.test_helpers import random_number, split_hash_word

# JWT (JSON Web Token): HMAC over "header.payload" keyed with the password, the algorithm named in
# the header. A new hash is always HS256, so that one run does not mix three hash lengths; the draw
# of which algorithm stays, so a seeded run draws what the perl did.

ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url(data):
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text):
  return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def random_jwt_salt():
  hashes = ["HS256"]

  alg = hashes[random_number(0, len(hashes) - 1)]

  key = random_number(1, 100000000)
  val = random_number(1, 100000000)

  header = json.dumps({"alg": alg}, separators=(",", ":")).encode()
  payload = json.dumps({str(key): val}, separators=(",", ":")).encode()

  return b64url(header) + "." + b64url(payload)


def module_constraints():
  return [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt = salt or random_jwt_salt()

  header = json.loads(b64url_decode(salt.split(".")[0]))

  algo = ALGS.get(header.get("alg"))

  if algo is None:
    raise ValueError("not supported hash")

  return "%s.%s" % (salt, b64url(hmac.new(word, salt.encode(), algo).digest()))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split(".")

  if len(data) != 3:
    return None

  try:
    return (module_generate_hash(word, data[0] + "." + data[1]), word)
  except (ValueError, binascii.Error):
    return None
