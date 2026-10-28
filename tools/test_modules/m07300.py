#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

# IPMI2 RAKP HMAC-SHA1: the salt is the RAKP message, printed in hex before the digest.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 256],
      },
      'optimized': {
        'password_length': [0, 55],
        'salt_length': [32, 32],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode("latin-1")

  return "%s:%s" % (salt_bytes.hex(), hmac.new(word, salt_bytes, hashlib.sha1).hexdigest())


def module_verify_hash(line):
  parts = line.split(b":", 2)

  if len(parts) != 3:
    return None

  salt_hex, _, word = parts

  try:
    salt = bytes.fromhex(salt_hex.decode()).decode("latin-1")
  except ValueError:
    return None

  return (module_generate_hash(word, salt), word)
