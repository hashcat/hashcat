#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import passlib_pbkdf2

# Python passlib pbkdf2-sha1, see lib/passlib_pbkdf2.py.


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return passlib_pbkdf2.generate_hash("$pbkdf2$", "sha1", word, salt.encode("latin-1") if salt else None, iterations)


def module_verify_hash(line):
  return passlib_pbkdf2.verify_hash("$pbkdf2$", "sha1", line)
