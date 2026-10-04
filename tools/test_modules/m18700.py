#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_word

# Java Object hashCode (): h = 31 * h + c over the bytes, 32 bits of it. The perl stopped at the first
# zero byte, and so does this.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  h = 0

  for c in word:
    if c == 0:
      break

    h = (h * 31 + c) & 0xffffffff

  return "%08x" % h


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
