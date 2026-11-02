#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import streebog

# HMAC-Streebog-256, keyed with the password.


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  return "%s:%s" % (streebog.hmac_digest(256, word, salt_bytes), salt)


def module_verify_hash(line):
  parts = line.split(b":", 2)

  if len(parts) != 3:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt.decode()), word)
