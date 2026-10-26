#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import streebog

# HMAC-Streebog-512, keyed with the salt.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  return "%s:%s" % (streebog.hmac_digest(512, salt_bytes, word), salt)


def module_verify_hash(line):
  parts = line.split(b":", 2)

  if len(parts) != 3:
    return None

  _, salt, word = parts

  return (module_generate_hash(word, salt.decode()), word)
