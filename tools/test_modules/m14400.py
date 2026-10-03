#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# sha1(CX): ten rounds of SHA-1 over --salt--, the last digest and --pass----.


def module_constraints():
  return [[0, 235], [20, 20], [0, 24], [20, 20], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  begin = b"--" + salt.encode() + b"--"
  end = b"--" + word + b"----"

  digest = hashlib.sha1(begin + end).hexdigest()

  for _ in range(1, 10):
    digest = hashlib.sha1(begin + digest.encode() + end).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
