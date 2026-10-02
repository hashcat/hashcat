#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import shacrypt

# sha512crypt $6$, SHA512 (Unix), see lib/shacrypt.py. A rounds field is clamped to what the format
# allows, 1000 to 999999999, and printed; without one the count is the default 5000.


def sha512(data):
  return hashlib.sha512(data).digest()


def module_constraints():
  return [[0, 256], [0, 16], [0, 15], [0, 16], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt = salt[:16]

  if iterations is None:
    return "$6$%s$%s" % (salt, shacrypt.crypt_bin(sha512, 512, word, salt.encode(), 5000))

  rounds = min(max(int(iterations), 1000), 999999999)

  return "$6$rounds=%d$%s$%s" % (rounds, salt, shacrypt.crypt_bin(sha512, 512, word, salt.encode(), rounds))


def module_verify_hash(line):
  parsed = shacrypt.parse(line)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
