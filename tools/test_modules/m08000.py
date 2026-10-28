#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

# Sybase ASE: SHA-256 over the password widened to UTF-16BE byte by byte, zero padded to 510 bytes,
# then the 8 byte salt.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': None,
      'optimized': {
        'password_length': [0, 27],
        'salt_length': [16, 16],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  wide = word.decode("latin-1").encode("utf-16-be")

  digest = hashlib.sha256(wide + b"\x00" * (510 - len(word) * 2) + bytes.fromhex(salt)).hexdigest()

  return "0xc007%s%s" % (salt, digest)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  try:
    return (module_generate_hash(word, hash_in[6:22]), word)
  except ValueError:
    return None
