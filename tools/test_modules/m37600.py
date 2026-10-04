#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_hex_string, random_number, split_hash_word

# SASL DIGEST-MD5 (RFC 2831) authentication response. HA1 = md5(md5(user:realm:password):nonce:cnonce),
# HA2 = md5("AUTHENTICATE:" . uri), response = md5(HA1:nonce:nc:cnonce:qop:HA2). The challenge fields
# are the salt, drawn the same way the perl oracle drew them so a seeded run repeats.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _response(word, realm, username, nonce, cnonce, nc, qop, uri):
  ha2 = hashlib.md5(b"AUTHENTICATE:" + uri.encode("latin-1")).hexdigest()

  h_raw = hashlib.md5(username.encode("latin-1") + b":" + realm.encode("latin-1") + b":" + word).digest()

  ha1 = hashlib.md5(h_raw + b":" + nonce.encode("latin-1") + b":" + cnonce.encode("latin-1")).hexdigest()

  joined = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2

  return hashlib.md5(joined.encode("latin-1")).hexdigest()


def module_generate_hash(word, salt=None, realm=None, nonce=None, cnonce=None, nc=None, qop=None, uri=None, username=None):
  if realm is None:
    realm    = "REALM-" + random_hex_string(6)
    nonce    = random_hex_string(28)
    cnonce   = random_hex_string(32)
    nc       = "00000001"
    qop      = "auth"
    uri      = "ldap/" + random_hex_string(8).lower() + ".local"
    username = "user" + str(random_number(0, 9998))

  response = _response(word, realm, username, nonce, cnonce, nc, qop, uri)

  return "$sasl$DIGEST-MD5$%s$%s$%s$%s$%s$%s$%s$%s" % (realm, username, nonce, cnonce, nc, qop, uri, response)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$sasl$"):
    return None

  fields = hash_in.split("$")

  if len(fields) < 11 or fields[2] != "DIGEST-MD5":
    return None

  realm, username, nonce, cnonce, nc, qop, uri, response = fields[3:11]

  return (module_generate_hash(word, None, realm, nonce, cnonce, nc, qop, uri, username), word)
