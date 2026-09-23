#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import crypt_r

from lib import shacrypt

# sha256crypt $5$, SHA256 (Unix). crypt_r is libc's crypt, the same routine the perl module reached,
# so the crypt string matches byte for byte.


def module_constraints():
  return [[0, 256], [0, 20], [0, 15], [0, 20], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if iterations is None:
    setting = "$5$%s$" % salt
  else:
    setting = "$5$rounds=%d$%s$" % (int(iterations), salt)

  return crypt_r.crypt(word.decode("latin-1"), setting)


def module_verify_hash(line):
  parsed = shacrypt.parse(line, 30)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
