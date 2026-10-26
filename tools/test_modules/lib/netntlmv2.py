#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# NetNTLMv2 for 5600 (from the password) and 27100 (from the NT hash): HMAC-MD5 of the upper cased
# user and the domain in UTF-16LE keyed with the NT hash, then HMAC-MD5 of both challenges with that.

import hashlib
import hmac

from lib.test_helpers import random_count, random_hex_string, random_string


def random_client_challenge():
  return "0101000000000000" + random_hex_string(2 * 16) + "00000000" + random_hex_string(2 * random_count(20)) + "00"


def generate_hash(nthash, user, domain=None, srv_ch=None, cli_ch=None):
  if domain is None:
    domain = random_string(27 - len(user))

  if srv_ch is None:
    srv_ch = random_hex_string(2 * 8)

  if cli_ch is None:
    cli_ch = random_client_challenge()

  # perl's uc () folds ASCII only in a byte string, and so does bytes.upper ()

  identity = (user.encode().upper() + domain.encode()).decode("latin-1").encode("utf-16-le")

  key = hmac.new(nthash, identity, hashlib.md5).digest()

  digest = hmac.new(key, bytes.fromhex(srv_ch) + bytes.fromhex(cli_ch), hashlib.md5).hexdigest()

  return "%s::%s:%s:%s:%s" % (user, domain, srv_ch, digest, cli_ch)


def parse(line):
  # (user, domain, srv_ch, cli_ch, word) out of "user::domain:srv_ch:digest:cli_ch:word"

  idx1 = line.find(b"::")

  if idx1 == -1:
    return None

  idx2 = line.find(b":", idx1 + 2)

  if idx2 == -1:
    return None

  idx3 = line.find(b":", idx2 + 3 + 16 + 32)

  if idx3 == -1:
    return None

  return (line[:idx1].decode(), line[idx1 + 2:idx2].decode(), line[idx2 + 1:idx2 + 1 + 16].decode(),
          line[idx2 + 3 + 16 + 32:idx3].decode(), line[idx3 + 1:])
