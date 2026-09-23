#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_number, random_string

# SIP digest authentication (RFC 2617). HA1 is md5 of user:realm:password, HA2 is md5 of the method
# and URI, and the response is md5 of HA1, the nonce (with the qop fields when qop is set) and HA2.


def _md5_hex(data):
  return hashlib.md5(data).hexdigest()


def module_constraints():
  return [[0, 24], [1, 15], [0, 24], [1, 15], [-1, -1]]


def module_generate_hash(word, nonce, iterations=None, user=None, realm=None, nonce_count=None,
                         nonce_client=None, qop=None, method=None, uri_prefix=None,
                         uri_resource=None, uri_suffix=None, directive=None, uri_server=None):
  if user is None:
    user = random_string(random_number(1, 12 + 1))

  if method is None:
    method = random_string(random_number(1, 24 + 1))

  if uri_prefix is None:
    uri_prefix = random_string(random_number(1, 10 + 1))

  if uri_resource is None:
    uri_resource = random_string(random_number(1, 32 + 1))

  if uri_suffix is None:
    uri_suffix = random_string(random_number(1, 32 + 1))

  if directive is None:
    directive = "MD5"

  if uri_server is None:
    uri_server = random_string(random_number(1, 32 + 1))

  if directive != "MD5":
    return None

  if realm is None:
    realm_max_len = 55 - len(user) - 1 - len(word) - 1

    if realm_max_len < 1:
      realm_max_len = 1

    realm_max_len = min(20, realm_max_len)

    realm = random_string(random_number(1, realm_max_len + 1))

  if nonce_count is None or nonce_client is None or qop is None:
    if random_number(0, 1 + 1) == 1:
      qop = "auth"
      nonce_count = random_string(random_number(1, 10 + 1))
      nonce_client = random_string(random_number(1, 12 + 1))
    else:
      qop = ""
      nonce_count = ""
      nonce_client = ""

  uri = ""

  if len(uri_prefix) > 0:
    uri = uri_prefix + ":"

  uri += uri_resource

  if len(uri_suffix) > 0:
    uri += ":" + uri_suffix

  ha2 = _md5_hex((method + ":" + uri).encode("latin-1"))

  ha1 = _md5_hex((user + ":" + realm + ":").encode("latin-1") + word)

  if qop in ("auth", "auth-int"):
    tmp = nonce + ":" + nonce_count + ":" + nonce_client + ":" + qop
  else:
    tmp = nonce

  digest = _md5_hex((ha1 + ":" + tmp + ":" + ha2).encode("latin-1"))

  return "$sip$*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s" % (
    uri_server, uri_resource, user, realm, method, uri_prefix, uri_resource, uri_suffix, nonce,
    nonce_client, nonce_count, qop, directive, digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  digest, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = digest.split("*")

  if len(data) != 15:
    return None

  (signature, uri_server, uri_client, user, realm, method, uri_prefix, uri_resource, uri_suffix,
   nonce, nonce_client, nonce_count, qop, directive, digest_hash) = data

  if signature != "$sip$":
    return None

  return (module_generate_hash(word, nonce, user=user, realm=realm, nonce_count=nonce_count,
                               nonce_client=nonce_client, qop=qop, method=method,
                               uri_prefix=uri_prefix, uri_resource=uri_resource,
                               uri_suffix=uri_suffix, directive=directive, uri_server=uri_server),
          word)
