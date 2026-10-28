#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import MD4

from lib.test_helpers import split_hash_word

# hashlib has no MD4 wherever OpenSSL ships without the legacy provider, so this is pycryptodome's.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 27],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return MD4.new(word).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
