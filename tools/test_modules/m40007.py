#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from lib.test_helpers import split_hash_salt_word

# MODX Evolution, ManagerAPI::genHash () with the default algorithm UNCRYPT: h = md5 (pass . id) in
# hex, the digest is md5 (h . sha1 (h . pass)) and the stored value appends the first 8 hex
# characters of md5 (h). The salt is the user id.

LINE = re.compile(r"^uncrypt>([0-9a-fA-F]{32})([0-9a-fA-F]{8})?$")


def module_constraints():
  return [[0, 256], [1, 10], [-1, -1], [-1, -1], [-1, -1]]


def modx_uncrypt(word, salt, with_tail):
  h = hashlib.md5(word + salt.encode()).hexdigest().encode()

  digest = hashlib.md5(h + hashlib.sha1(h + word).hexdigest().encode()).hexdigest()

  if with_tail == True:
    digest += hashlib.md5(h).hexdigest()[0:8]

  return "uncrypt>%s:%s" % (digest, salt)


def module_generate_hash(word, salt, iterations=None):
  if salt is None or len(salt) == 0:
    salt = "1"

  return modx_uncrypt(word, salt, True)


def module_verify_hash(line):
  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, salt, word = parts

  m = LINE.match(hash_in)

  if m is None:
    return None

  with_tail = (len(hash_in) == (8 + 32 + 8))

  return (modx_uncrypt(word, salt, with_tail), word)
