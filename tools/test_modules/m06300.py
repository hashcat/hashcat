#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md5crypt
from lib.test_helpers import split_hash_word

# AIX {smd5}: md5crypt with an empty magic and the 1000 rounds the format fixes.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 8],
      },
      'optimized': {
        'password_length': [0, 15],
        'salt_length': [0, 8],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return "{smd5}" + md5crypt.md5_crypt(b"", 1000, word, salt.encode("latin-1"))


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  salt = hash_in[hash_in.find("}") + 1:hash_in.rfind("$")]

  return (module_generate_hash(word, salt), word)
