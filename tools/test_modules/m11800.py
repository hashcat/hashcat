#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import streebog

# Streebog-512, raw unsalted digest.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': None,
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return streebog.digest(512, word)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  word = line[idx + 1:]

  return (module_generate_hash(word, None), word)
