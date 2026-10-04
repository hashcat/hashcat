#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md5crypt, shacrypt

# Apache $apr1$ MD5: md5crypt with the magic $apr1$, see lib/md5crypt.py.


def module_constraints():
  return [[0, 256], [0, 8], [0, 15], [0, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  rounds = 1000

  if iterations is not None and int(iterations) > 0:
    rounds = int(iterations)

  return md5crypt.md5_crypt(b"$apr1$", rounds, word, salt.encode("latin-1"))


def module_verify_hash(line):
  parsed = shacrypt.parse(line)

  if parsed is None:
    return None

  _, salt, rounds, word = parsed

  return (module_generate_hash(word, salt, rounds), word)
