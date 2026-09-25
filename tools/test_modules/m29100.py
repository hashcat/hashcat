#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import hmac
import json

from lib.test_helpers import random_number, split_hash_word

# Flask Session Cookie: HMAC-SHA1 of the cookie keyed with HMAC-SHA1 of "cookie-session" keyed with
# the secret, see https://github.com/hashcat/hashcat/issues/3239.


def b64url(data):
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def random_flask_salt():
  header = json.dumps({"username": random_number(10000, 99999)}, separators=(",", ":")).encode()

  return b64url(header) + ".YjdgRQ"


def module_constraints():
  return [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt = salt or random_flask_salt()

  key = hmac.new(word, b"cookie-session", hashlib.sha1).digest()

  return "%s.%s" % (salt, b64url(hmac.new(key, salt.encode(), hashlib.sha1).digest()))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split(".")

  if len(data) != 3:
    return None

  return (module_generate_hash(word, data[0] + "." + data[1]), word)
