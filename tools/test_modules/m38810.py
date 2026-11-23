#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import openbsd_softraid
from lib.test_helpers import test_iteration_parameters

# OpenBSD softraid CRYPTO, created with OpenBSD 6.1 or later: the mask key is bcrypt_pbkdf.


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [128, 128],
      },
      'optimized': None,
      'combined_length': None,
      'association_parameters': [{"iterations": 1}, {"iterations": (2, 4)}],
    },
    'reduced': {'parameters': {'iterations_max': 2}},
  }


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, masked=None, iterations_max=None):
  if iterations is None:
    iterations = openbsd_softraid.random_iterations(openbsd_softraid.KDF_BCRYPT)

    if iterations_max is not None:
      iterations = min(iterations, int(iterations_max))

  return openbsd_softraid.generate_hash(openbsd_softraid.KDF_BCRYPT, word, salt, int(iterations), masked)


def module_verify_hash(line):
  return openbsd_softraid.verify_hash(openbsd_softraid.KDF_BCRYPT, line)
