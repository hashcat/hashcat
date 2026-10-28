#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import openbsd_softraid

from lib.test_helpers import test_iteration_parameters


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [128, 128],
      },
      'optimized': None,
      'combined_length': None,
    },
    'normal': {'ci_seconds': {'pure': 34, 'bridge': 2, 'edge': 117}},
    'reduced': {
      'parameters': {'iterations': 2},
      'ci_seconds': {'opt': 1, 'pure': 44, 'edge': 143},
    },
  }


# OpenBSD softraid CRYPTO, created before OpenBSD 6.1: the mask key is PBKDF2-HMAC-SHA1.


ITERATION_PARAMETERS = test_iteration_parameters(module_test_properties())


def module_generate_hash(word, salt, iterations=None, masked=None):
  if iterations is None:
    iterations = openbsd_softraid.random_iterations(openbsd_softraid.KDF_PBKDF2)

  return openbsd_softraid.generate_hash(openbsd_softraid.KDF_PBKDF2, word, salt, int(iterations), masked)


def module_verify_hash(line):
  return openbsd_softraid.verify_hash(openbsd_softraid.KDF_PBKDF2, line)
