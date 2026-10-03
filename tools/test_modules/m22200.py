#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

# Citrix NetScaler (SHA512): 2, the 8 character salt, then SHA-512 over the salt, the password and a
# terminating zero byte.


def module_constraints():
  return [[0, 256], [8, 8], [0, 54], [8, 8], [8, 54]]


def module_generate_hash(word, salt, iterations=None):
  return "2%s%s" % (salt, hashlib.sha512(salt.encode() + word + b"\x00").hexdigest())


def module_verify_hash(line):
  salt = line[1:9].decode(errors="replace")

  idx = line.find(b":", 9)

  if idx < 10:
    return None

  word = line[idx + 1:]

  return (module_generate_hash(word, salt), word)
