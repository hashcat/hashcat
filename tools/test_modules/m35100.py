#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import shacrypt

# sm3crypt: the sha256crypt construction over ShangMi 3, which OpenSSL provides to hashlib by name.
#
# There is no pure kernel: OpenCL/ carries only m35100-optimized.cl, so hashcat falls back to it even
# under -P and module_pw_max () then caps the password at 15.


def sm3(data):
  return hashlib.new("sm3", data).digest()


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 15], [0, 20], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  loops = 5000 if iterations is None else int(iterations)

  digest = shacrypt.crypt_bin(sm3, 256, word, salt.encode(), loops)

  if iterations is None:
    return "$sm3$%s$%s" % (salt, digest)

  return "$sm3$rounds=%d$%s$%s" % (loops, salt, digest)


def module_verify_hash(line):
  parsed = shacrypt.parse(line, 30)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
