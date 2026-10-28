#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import shacrypt

# sm3crypt: the sha256crypt construction over ShangMi 3, which OpenSSL provides to hashlib by name.
# The optimized kernel takes a password of at most 15 bytes, see module_pw_max ().


def sm3(data):
  return hashlib.new("sm3", data).digest()


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 20],
      },
      'optimized': {
        'password_length': [0, 15],
        'salt_length': [0, 20],
      },
      'combined_length': None,
    },
  }


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
