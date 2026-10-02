#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import shacrypt

# sha256crypt $5$, SHA256 (Unix), see lib/shacrypt.py. The perl module used a salt up to 20 bytes and
# did not truncate it, unlike libc crypt which stops at 16, so this hashes the whole salt.


def sha256(data):
  return hashlib.sha256(data).digest()


def module_constraints():
  return [[0, 256], [0, 20], [0, 15], [0, 20], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if iterations is None:
    return "$5$%s$%s" % (salt, shacrypt.crypt_bin(sha256, 256, word, salt.encode(), 5000))

  rounds = min(max(int(iterations), 1000), 999999999)

  return "$5$rounds=%d$%s$%s" % (rounds, salt, shacrypt.crypt_bin(sha256, 256, word, salt.encode(), rounds))


def module_verify_hash(line):
  parsed = shacrypt.parse(line, 30)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
