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

# Perl Mojolicious session cookie: name=value--HMAC-SHA256(name=value) keyed with the password. The
# value is a JSON payload padded to 1025 bytes, base64 encoded with - for =.


def random_mojolicious_salt():
  key = random_number(1, 100000000)
  val = random_number(1, 100000000)

  payload = json.dumps({str(key): val}, separators=(",", ":")).encode()

  payload += b"Z" * (1025 - len(payload))

  return "mojolicious=" + base64.b64encode(payload).decode().replace("=", "-")


def module_constraints():
  return [[0, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt = salt or random_mojolicious_salt()

  name, value = salt.split("=")[:2]

  cookie = "%s=%s" % (name, value)

  return "%s--%s" % (cookie, hmac.new(word, cookie.encode(), hashlib.sha256).hexdigest())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  idx = hash_in.rfind("--")

  if idx < 1:
    return None

  return (module_generate_hash(word, hash_in[:idx]), word)
