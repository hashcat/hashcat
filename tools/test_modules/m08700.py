#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import lotus
from lib.test_helpers import split_hash_word

# Lotus Notes/Domino 6, the salted account hash: the digest of the password is wrapped as an upper
# case "(hex)" string, prepended with the 5 byte salt, run through the mix again, and the salt and
# result are stored in Domino base64. See lib/lotus.py.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 32], [5, 5], [0, 55]]


def module_generate_hash(word, salt, iterations=None, char=None):
  state = lotus.big_md(list(word))

  wrapped = "(" + bytes(state).hex().upper() + ")"

  digest = bytes(lotus.big_md(list((salt + wrapped).encode("latin-1")), 34))

  return "(G%s)" % lotus.encode(salt.encode("latin-1") + digest, char)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if len(hash_in) < 3:
    return None

  try:
    _, salt, char = lotus.decode(hash_in[2:-1])
  except (ValueError, IndexError):
    return None

  return (module_generate_hash(word, salt.decode("latin-1"), None, char), word)
