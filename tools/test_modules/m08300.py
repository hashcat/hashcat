#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_numeric_string

# DNSSEC NSEC3. The hashed owner name is iterated SHA1 over the DNS wire-format name (the lowercased
# password joined to the domain) followed by the salt, printed in base32hex (labels split on '.',
# each length prefixed, root null terminator). The label bytes go in raw, which is what hashcat
# hashes: it does not punycode a non ASCII label, so a non ASCII password cracks with the raw wire
# encoding and would not with an xn-- form. The .pm computes the same thing directly with Digest::SHA.
#
# The salt line is "<hash>:<domain>:<salthex>:<iter>". get_random_dnssec_salt () builds the domain
# by prefixing a '.' and appending a fresh throwaway salt as a third ':' field that the two element
# split then drops, so it recovers the real salt from the middle field. verify strips the leading
# '.' from the domain first, because generate_hash re-adds it; without that the name gets two dots
# and the round trip breaks.

B32HEX = "0123456789abcdefghijklmnopqrstuv"


def module_constraints():
  return [[1, 63], [1, 63], [1, 32], [1, 24], [1, 44]]


def _encode_base32hex(digest):
  bits = "".join(format(b, "08b") for b in digest)

  return "".join(B32HEX[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def _name2wire(name):
  # name is lowercased bytes, split into DNS labels on '.', each length prefixed, root terminated

  return b"".join(bytes([len(label)]) + label for label in name.split(b".")) + b"\x00"


def _name2hash(name, iterations, salt_hex):
  salt = bytes.fromhex(salt_hex)

  digest = hashlib.sha1(_name2wire(name) + salt).digest()

  for _ in range(iterations):
    digest = hashlib.sha1(digest + salt).digest()

  return _encode_base32hex(digest)


def _get_random_dnssec_salt(domain):
  return "." + domain + ":" + random_numeric_string(8)


def module_generate_hash(word, salt, iterations=None):
  iterations = 1 if iterations is None else int(iterations)

  combined_salt = _get_random_dnssec_salt(salt)

  parts = combined_salt.split(":")

  domain, salt_hex = parts[0], parts[1]

  name = (word + domain.encode("latin-1")).lower()

  hash_buf = _name2hash(name, iterations, salt_hex)

  return "%s:%s:%s:%d" % (hash_buf, domain, salt_hex, iterations)


def module_verify_hash(line):
  datas = line.split(b":")

  if len(datas) != 5:
    return None

  domain   = datas[1].decode("latin-1")
  salt_hex = datas[2].decode("latin-1")

  try:
    iterations = int(datas[3])
  except ValueError:
    return None

  word = datas[4]

  # get_random_dnssec_salt () re-adds the leading '.', so hand it the bare domain
  bare_domain = domain[1:] if domain.startswith(".") else domain

  new_hash = module_generate_hash(word, bare_domain + ":" + salt_hex, iterations)

  return (new_hash, word)
