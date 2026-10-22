#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import virtualbox

# VirtualBox, PBKDF2-HMAC-SHA256 and AES-256-XTS, see lib/virtualbox.py.

KEY_LEN = 64

ITER1 = 160000


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return virtualbox.generate_hash(KEY_LEN, ITER1, word, salt, iterations)


def module_verify_hash(line):
  return virtualbox.verify_hash(KEY_LEN, ITER1, line)
