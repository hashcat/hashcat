#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md5crypt, shacrypt
from lib.test_helpers import test_iteration_parameters

# AIX {smd5}: md5crypt with an empty magic and an optional encoded round count.


def module_test_properties():
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
    'reduced': {'parameters': {'iterations': 2}, 'copy_hash': True},
  }


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None):
  rounds = 1000 if iterations is None else int(iterations)

  return "{smd5}" + md5crypt.md5_crypt(b"", rounds, word, salt.encode("latin-1"))


def module_verify_hash(line):
  if not line.startswith(b"{smd5}"):
    return None

  parts = shacrypt.parse(b"$1$" + line[6:])

  if parts is None:
    return None

  _, salt, rounds, word = parts

  return (module_generate_hash(word, salt, rounds), word)
