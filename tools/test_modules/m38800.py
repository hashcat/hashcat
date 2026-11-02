#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import openbsd_softraid

# OpenBSD softraid CRYPTO, created before OpenBSD 6.1: the mask key is PBKDF2-HMAC-SHA1.


def module_constraints():
  return [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, masked=None):
  if iterations is None:
    iterations = openbsd_softraid.random_iterations(openbsd_softraid.KDF_PBKDF2)

  return openbsd_softraid.generate_hash(openbsd_softraid.KDF_PBKDF2, word, salt, int(iterations), masked)


def module_verify_hash(line):
  return openbsd_softraid.verify_hash(openbsd_softraid.KDF_PBKDF2, line)
