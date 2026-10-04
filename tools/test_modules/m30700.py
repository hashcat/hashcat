#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.sha256_state import sha256_from_state

# Anope IRC Services (enc_sha256): SHA-256 of the password from a state that is the 32 byte salt, see
# lib/sha256_state.py.


def module_constraints():
  return [[0, 256], [64, 64], [0, 55], [64, 64], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  state = [int(salt[i:i + 8], 16) for i in range(0, 64, 8)]

  return "sha256:%s:%s" % (sha256_from_state(state, word).hex(), salt)


def module_verify_hash(line):
  parts = line.split(b":", 3)

  if len(parts) != 4 or parts[0] != b"sha256":
    return None

  word = parts[3]

  try:
    return (module_generate_hash(word, parts[2].decode()), word)
  except ValueError:
    return None
