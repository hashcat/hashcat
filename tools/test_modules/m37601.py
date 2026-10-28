#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# POP3 APOP: the server banner is the salt, and the response is md5(banner . password).


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [10, 128],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [10, 55],
      },
      'combined_length': [0, 55],
    },
  }


def module_generate_hash(word, salt, iterations=None):
  digest = hashlib.md5(salt.encode("latin-1") + word).hexdigest()

  return "$apop$%s$%s" % (salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$apop$"):
    return None

  fields = hash_in.split("$")

  if len(fields) < 4:
    return None

  return (module_generate_hash(word, fields[2]), word)
