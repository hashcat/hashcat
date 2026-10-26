#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_salt_word

# Skype: the salt, "\nskyper\n" and the password, so both take 8 less than the kernel's buffer.


def module_constraints():
  return [[0, 247], [0, 247], [0, 47], [0, 43], [0, 47]]


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.md5(salt.encode() + b"\nskyper\n" + word).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt), word)
