#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import uuid

from lib.test_helpers import split_hash_salt_word

# UUID v5 (RFC 4122): sha1 of the namespace UUID's 16 bytes and the name, with the version and the
# variant set. This is uuid.uuid5 (), computed here from the bytes so that a name need not be UTF-8.
# The 32 digit salt is the namespace UUID in hex.


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  ns = uuid.UUID(hex=salt)

  digest = hashlib.sha1(ns.bytes + word).digest()

  return "%s:%s" % (uuid.UUID(bytes=digest[:16], version=5), ns)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  try:
    ns = uuid.UUID(salt)
  except ValueError:
    return None

  return (module_generate_hash(word, ns.hex), word)
