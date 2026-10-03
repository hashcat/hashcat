#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import keccak

from lib.test_helpers import split_hash_word

# Keccak-224 (the original padding, not SHA3).


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 31], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return keccak.new(digest_bits=224, data=word).hexdigest()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
