#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import streebog

# Streebog-256, raw unsalted digest.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return streebog.digest(256, word)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  word = line[idx + 1:]

  return (module_generate_hash(word, None), word)
